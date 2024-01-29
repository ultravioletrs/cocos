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
	"os"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/mdlayher/vsock"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/agent/api"
	agentgrpc "github.com/ultravioletrs/cocos/agent/api/grpc"
	"github.com/ultravioletrs/cocos/agent/events"
	"github.com/ultravioletrs/cocos/internal"
	"github.com/ultravioletrs/cocos/internal/server"
	grpcserver "github.com/ultravioletrs/cocos/internal/server/grpc"
	"github.com/ultravioletrs/cocos/manager"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	svcName        = "agent"
	defSvcGRPCPort = "7002"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	cfg, err := readConfig()
	if err != nil {
		log.Fatalf("failed to read agent configuration from vsock %s", err.Error())
	}

	ac, err := createCertFiles(cfg.AgentConfig)
	if err != nil {
		log.Fatalf("failed to create cert files %s", err.Error())
	}
	cfg.AgentConfig = ac

	conn, err := vsock.Dial(vsock.Host, manager.VsockLogsPort, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	logger, err := mglog.New(conn, cfg.AgentConfig.LogLevel)
	if err != nil {
		log.Print(err.Error())
		return
	}

	eventSvc, err := events.New(svcName, cfg.ID)
	if err != nil {
		log.Printf("failed to create events service %s", err.Error())
		return
	}
	defer eventSvc.Close()
	svc := newService(ctx, logger, eventSvc)

	if _, err := svc.Run(cfg); err != nil {
		if err := eventSvc.SendEvent("init", "failed", json.RawMessage{}); err != nil {
			logger.Warn(err.Error())
		}
		logger.Error(fmt.Sprintf("failed to run computation with err: %s", err))
		return
	}

	grpcServerConfig := server.Config{
		Port:         cfg.AgentConfig.Port,
		Host:         cfg.AgentConfig.Host,
		CertFile:     cfg.AgentConfig.CertFile,
		KeyFile:      cfg.AgentConfig.KeyFile,
		ServerCAFile: cfg.AgentConfig.ServerCAFile,
		ClientCAFile: cfg.AgentConfig.ClientCAFile,
	}

	registerAgentServiceServer := func(srv *grpc.Server) {
		reflection.Register(srv)
		agent.RegisterAgentServiceServer(srv, agentgrpc.NewServer(svc))
	}
	gs := grpcserver.New(ctx, cancel, svcName, grpcServerConfig, registerAgentServiceServer, logger)

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

func newService(ctx context.Context, logger *slog.Logger, eventSvc events.Service) agent.Service {
	svc := agent.New(ctx, logger, eventSvc)

	svc = api.LoggingMiddleware(svc, logger)
	counter, latency := internal.MakeMetrics(svcName, "api")
	svc = api.MetricsMiddleware(svc, counter, latency)

	return svc
}

func readConfig() (agent.Computation, error) {
	l, err := vsock.Listen(manager.VsockConfigPort, nil)
	if err != nil {
		return agent.Computation{}, err
	}
	defer l.Close()
	conn, err := l.Accept()
	if err != nil {
		return agent.Computation{}, err
	}
	defer conn.Close()
	b := make([]byte, 1024)
	n, err := conn.Read(b)
	if err != nil {
		return agent.Computation{}, err
	}
	ac := agent.Computation{
		AgentConfig: agent.AgentConfig{},
	}
	if err := json.Unmarshal(b[:n], &ac); err != nil {
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

func createCertFiles(cfg agent.AgentConfig) (agent.AgentConfig, error) {
	if cfg.CertFile != "" {
		path, err := createFile(cfg.CertFile)
		if err != nil {
			return cfg, err
		}
		cfg.CertFile = path
	}
	if cfg.KeyFile != "" {
		path, err := createFile(cfg.KeyFile)
		if err != nil {
			return cfg, err
		}
		cfg.KeyFile = path
	}
	if cfg.ServerCAFile != "" {
		path, err := createFile(cfg.ServerCAFile)
		if err != nil {
			return cfg, err
		}
		cfg.ServerCAFile = path
	}
	if cfg.ClientCAFile != "" {
		path, err := createFile(cfg.ClientCAFile)
		if err != nil {
			return cfg, err
		}
		cfg.ClientCAFile = path
	}
	return cfg, nil
}

func createFile(content string) (string, error) {
	provider := uuid.New()
	id, err := provider.ID()
	if err != nil {
		return "", err
	}
	file, err := os.Create(fmt.Sprintf("%s.txt", id))
	if err != nil {
		return "", err
	}
	defer file.Close()
	if _, err = io.WriteString(file, content); err != nil {
		return "", err
	}
	return file.Name(), err
}
