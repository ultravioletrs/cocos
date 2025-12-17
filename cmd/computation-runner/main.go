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
	pb "github.com/ultravioletrs/cocos/agent/runner"
	runnerevents "github.com/ultravioletrs/cocos/agent/runner/events"
	"github.com/ultravioletrs/cocos/agent/runner/service"
	logclient "github.com/ultravioletrs/cocos/pkg/clients/grpc/log"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

const (
	svcName    = "computation-runner"
	socketPath = "/run/cocos/runner.sock"
)

type config struct {
	LogLevel     string `env:"RUNNER_LOG_LEVEL,AGENT_LOG_LEVEL" envDefault:"debug"`
	LogForwarder string `env:"LOG_FORWARDER_SOCKET" envDefault:"/run/cocos/log.sock"`
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

	// Connect to Log Forwarder
	logClient, err := logclient.NewClient(cfg.LogForwarder)
	if err != nil {
		logger.Warn(fmt.Sprintf("failed to connect to log-forwarder: %s. Events will not be forwarded.", err))
	} else {
		defer logClient.Close()
	}

	eventSvc := runnerevents.NewAdapter(logClient, svcName)

	// Remove existing socket if it exists
	if _, err := os.Stat(socketPath); err == nil {
		if err := os.Remove(socketPath); err != nil {
			logger.Error(fmt.Sprintf("failed to remove existing socket: %s", err))
			exitCode = 1
			return
		}
	}

	dir := socketPath[:len(socketPath)-len("/runner.sock")]
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

	grpcServer := grpc.NewServer()
	svc := service.New(logger, eventSvc)
	pb.RegisterComputationRunnerServer(grpcServer, svc)

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
