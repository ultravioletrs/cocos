// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"time"

	"github.com/absmach/magistrala/pkg/prometheus"
	"github.com/cenkalti/backoff/v4"
	"github.com/google/go-sev-guest/client"
	"github.com/mdlayher/vsock"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/agent/api"
	agentgrpc "github.com/ultravioletrs/cocos/agent/api/grpc"
	"github.com/ultravioletrs/cocos/agent/auth"
	"github.com/ultravioletrs/cocos/agent/events"
	"github.com/ultravioletrs/cocos/agent/quoteprovider"
	agentlogger "github.com/ultravioletrs/cocos/internal/logger"
	"github.com/ultravioletrs/cocos/internal/server"
	grpcserver "github.com/ultravioletrs/cocos/internal/server/grpc"
	"github.com/ultravioletrs/cocos/manager"
	"github.com/ultravioletrs/cocos/manager/qemu"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	svcName        = "agent"
	defSvcGRPCPort = "7002"
	retryInterval  = 5 * time.Second
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	cfg, err := readConfig()
	if err != nil {
		log.Fatalf("failed to read agent configuration from vsock %s", err.Error())
	}

	conn, err := dialVsock()
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.AgentConfig.LogLevel)); err != nil {
		log.Println(err)
		return
	}
	handler := agentlogger.NewProtoHandler(conn, &slog.HandlerOptions{Level: level}, cfg.ID)
	logger := slog.New(handler)

	eventSvc, err := events.New(svcName, cfg.ID, manager.ManagerVsockPort)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create events service %s", err.Error()))
		return
	}
	defer eventSvc.Close()

	qp, err := quoteprovider.GetQuoteProvider()
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create quote provider %s", err.Error()))
		return
	}

	svc := newService(ctx, logger, eventSvc, cfg, qp)

	grpcServerConfig := server.Config{
		Port:         cfg.AgentConfig.Port,
		Host:         cfg.AgentConfig.Host,
		CertFile:     cfg.AgentConfig.CertFile,
		KeyFile:      cfg.AgentConfig.KeyFile,
		ServerCAFile: cfg.AgentConfig.ServerCAFile,
		ClientCAFile: cfg.AgentConfig.ClientCAFile,
		AttestedTLS:  cfg.AgentConfig.AttestedTls,
	}

	registerAgentServiceServer := func(srv *grpc.Server) {
		reflection.Register(srv)
		agent.RegisterAgentServiceServer(srv, agentgrpc.NewServer(svc))
	}

	authSvc, err := auth.New(cfg)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create auth service %s", err.Error()))
		return
	}

	gs := grpcserver.New(ctx, cancel, svcName, grpcServerConfig, registerAgentServiceServer, logger, qp, authSvc)

	g.Go(func() error {
		for {
			if _, err := io.Copy(io.Discard, conn); err != nil {
				log.Printf("vsock connection lost: %v, reconnecting...", err)
				conn.Close()
				conn, err = dialVsock()
				if err != nil {
					log.Fatal("failed to reconnect: ", err)
				}
				handler = agentlogger.NewProtoHandler(conn, &slog.HandlerOptions{Level: level})
				logger = slog.New(handler)
			}
			time.Sleep(retryInterval)
		}
	})

	g.Go(func() error {
		return gs.Start()
	})

	g.Go(func() error {
		return server.StopHandler(ctx, cancel, logger, svcName, gs)
	})

	if err := g.Wait(); err != nil {
		logger.Error(fmt.Sprintf("%s service terminated: %s", svcName, err))
	}
}

func newService(ctx context.Context, logger *slog.Logger, eventSvc events.Service, cmp agent.Computation, qp client.QuoteProvider) agent.Service {
	svc := agent.New(ctx, logger, eventSvc, cmp, qp)

	svc = api.LoggingMiddleware(svc, logger)
	counter, latency := prometheus.MakeMetrics(svcName, "api")
	svc = api.MetricsMiddleware(svc, counter, latency)

	return svc
}

func readConfig() (agent.Computation, error) {
	l, err := vsock.Listen(qemu.VsockConfigPort, nil)
	if err != nil {
		return agent.Computation{}, err
	}
	defer l.Close()

	conn, err := l.Accept()
	if err != nil {
		return agent.Computation{}, err
	}
	defer conn.Close()

	var buffer []byte
	for {
		chunk := make([]byte, 1024)
		n, err := conn.Read(chunk)
		if err != nil {
			if err == io.EOF {
				break
			}
			return agent.Computation{}, err
		}
		buffer = append(buffer, chunk[:n]...)
	}

	ac := agent.Computation{
		AgentConfig: agent.AgentConfig{},
	}
	if err := json.Unmarshal(buffer, &ac); err != nil {
		return agent.Computation{}, err
	}
	if ac.AgentConfig.LogLevel == "" {
		ac.AgentConfig.LogLevel = "info"
	}
	if ac.AgentConfig.Port == "" {
		ac.AgentConfig.Port = defSvcGRPCPort
	}
	return ac, nil
}

func dialVsock() (*vsock.Conn, error) {
	var conn *vsock.Conn
	var err error

	err = backoff.Retry(func() error {
		conn, err = vsock.Dial(vsock.Host, manager.ManagerVsockPort, nil)
		if err == nil {
			log.Println("vsock connection established")
			return nil
		}
		log.Printf("vsock connection failed, retrying in %s... Error: %v", retryInterval, err)
		return err
	}, backoff.NewExponentialBackOff())
	if err != nil {
		return nil, err
	}

	return conn, nil
}
