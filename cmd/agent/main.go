// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/uuid"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/agent/api"
	agentgrpc "github.com/ultravioletrs/cocos/agent/api/grpc"
	"github.com/ultravioletrs/cocos/internal"
	"github.com/ultravioletrs/cocos/internal/events"
	"github.com/ultravioletrs/cocos/internal/server"
	grpcserver "github.com/ultravioletrs/cocos/internal/server/grpc"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	svcName        = "agent"
	envPrefixGRPC  = "AGENT_GRPC_"
	defSvcGRPCPort = "7002"
)

var errComputationNotFound = errors.New("computation not found in command line")

type config struct {
	LogLevel              string `json:"log_level"`
	InstanceID            string `json:"instance_id"`
	NotificationServerURL string `json:"notification_server_url"`
	Host                  string `json:"host"`
	Port                  string `json:"port"`
	CertFile              string `json:"cert_file"`
	KeyFile               string `json:"server_key"`
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	var cfg config

	logger, err := mglog.New(os.Stdout, cfg.LogLevel)
	if err != nil {
		log.Fatalf(err.Error())
	}

	if cfg.InstanceID == "" {
		cfg.InstanceID, err = uuid.New().ID()
		if err != nil {
			log.Fatalf("Failed to generate instanceID: %s", err)
		}
	}

	eventSvc := events.New(svcName, cfg.NotificationServerURL)
	svc := newService(ctx, logger, eventSvc)

	ac, err := extractComputationValue()
	if err != nil {
		logger.Fatal(fmt.Sprintf("computation not loaded from cmdline : %s", err.Error()))
	}
	if _, err := svc.Run(ctx, ac); err != nil {
		if err := eventSvc.SendEvent("init", ac.ID, "failed", json.RawMessage{}); err != nil {
			logger.Warn(err.Error())
		}
		logger.Fatal(fmt.Sprintf("failed to run computation with err: %s", err))
	}

	grpcServerConfig := server.Config{
		Port: defSvcGRPCPort,
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

func newService(ctx context.Context, logger mglog.Logger, eventSvc events.Service) agent.Service {
	svc := agent.New(ctx, logger, eventSvc)

	svc = api.LoggingMiddleware(svc, logger)
	counter, latency := internal.MakeMetrics(svcName, "api")
	svc = api.MetricsMiddleware(svc, counter, latency)

	return svc
}

// extractComputationValue to extract computation value from the command line.
func extractComputationValue() (agent.Computation, error) {
	cmdLineBytes, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return agent.Computation{}, err
	}
	cmdLine := string(cmdLineBytes)
	paramPrefix := "computation="
	index := strings.Index(string(cmdLine), paramPrefix)

	if index == -1 {
		return agent.Computation{}, errComputationNotFound
	}

	start := index + len(paramPrefix)
	end := strings.Index(cmdLine[start:], " ")

	cmpUnescaped := cmdLine[start : start+end]
	var ac agent.Computation
	if end == -1 {
		cmpUnescaped = cmdLine[start:]
	}

	if err := json.Unmarshal([]byte(cmpUnescaped), &ac); err != nil {
		return agent.Computation{}, err
	}
	return ac, nil
}
