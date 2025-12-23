// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	mglog "github.com/absmach/supermq/logger"
	"github.com/caarlos0/env/v11"
	"github.com/ultravioletrs/cocos/agent/cvms"
	pb "github.com/ultravioletrs/cocos/agent/log"
	"github.com/ultravioletrs/cocos/agent/log/service"
	"github.com/ultravioletrs/cocos/pkg/clients"
	cvmsgrpc "github.com/ultravioletrs/cocos/pkg/clients/grpc/cvm"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

const (
	svcName          = "log-forwarder"
	socketPath       = "/run/cocos/log.sock"
	envPrefixCVMGRPC = "AGENT_CVM_GRPC_"
)

type config struct {
	LogLevel string `env:"LOG_FORWARDER_LOG_LEVEL" envAlternate:"AGENT_LOG_LEVEL" envDefault:"debug"`
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	var cfg config
	if err := env.Parse(&cfg); err != nil {
		fmt.Printf("failed to load %s configuration : %s\n", svcName, err)
		os.Exit(1)
	}

	var exitCode int
	defer mglog.ExitWithError(&exitCode)

	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		fmt.Println(err)
		exitCode = 1
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	// Remove existing socket if it exists
	if _, err := os.Stat(socketPath); err == nil {
		if err := os.Remove(socketPath); err != nil {
			logger.Error(fmt.Sprintf("failed to remove existing socket: %s", err))
			exitCode = 1
			return
		}
	}

	dir := socketPath[:len(socketPath)-len("/log.sock")]
	if err := os.MkdirAll(dir, 0o755); err != nil {
		logger.Error(fmt.Sprintf("failed to create socket directory: %s", err))
		exitCode = 1
		return
	}

	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to listen on socket: %s", err))
		exitCode = 1
		return
	}

	if err := os.Chmod(socketPath, 0o777); err != nil {
		logger.Error(fmt.Sprintf("failed to chmod socket: %s", err))
		exitCode = 1
		return
	}

	// Connect to Manager
	cvmGrpcConfig := clients.StandardClientConfig{}
	if err := env.ParseWithOptions(&cvmGrpcConfig, env.Options{Prefix: envPrefixCVMGRPC}); err != nil {
		logger.Error(fmt.Sprintf("failed to load %s gRPC client configuration : %s", svcName, err))
		exitCode = 1
		return
	}

	cvmClient, cvmsClient, err := cvmsgrpc.NewCVMClient(cvmGrpcConfig)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to connect to CVM manager: %s", err))
		exitCode = 1
		return
	}
	defer cvmClient.Close()

	// Create stream to Manager
	stream, err := cvmsClient.Process(ctx)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create stream to manager: %s", err))
		exitCode = 1
		return
	}

	logQueue := make(chan *cvms.ClientStreamMessage, 1000)

	grpcServer := grpc.NewServer()
	svc := service.New(logger, cvmsClient, logQueue)
	pb.RegisterLogCollectorServer(grpcServer, svc)

	// Log Consumer Goroutine
	g.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case msg := <-logQueue:
				if err := stream.Send(msg); err != nil {
					logger.Error(fmt.Sprintf("failed to send log to manager: %s", err))
					// Reconnect logic would go here
				}
			}
		}
	})

	g.Go(func() error {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(ch)

		select {
		case <-ch:
			logger.Info("Received signal, shutting down...")
			cancel()
			grpcServer.GracefulStop()
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	g.Go(func() error {
		logger.Info(fmt.Sprintf("%s started on %s", svcName, socketPath))
		return grpcServer.Serve(lis)
	})

	if err := g.Wait(); err != nil {
		logger.Error(fmt.Sprintf("%s terminated: %s", svcName, err))
	}
}
