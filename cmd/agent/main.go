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
	"strconv"
	"strings"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/messaging"
	"github.com/absmach/magistrala/pkg/messaging/brokers"
	"github.com/absmach/magistrala/pkg/uuid"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/agent/api"
	agentgrpc "github.com/ultravioletrs/cocos/agent/api/grpc"
	"github.com/ultravioletrs/cocos/agent/tracing"
	"github.com/ultravioletrs/cocos/internal"
	"github.com/ultravioletrs/cocos/internal/env"
	jaegerclient "github.com/ultravioletrs/cocos/internal/jaeger"
	"github.com/ultravioletrs/cocos/internal/server"
	grpcserver "github.com/ultravioletrs/cocos/internal/server/grpc"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	svcName        = "agent"
	envPrefixHTTP  = "AGENT_HTTP_"
	envPrefixGRPC  = "AGENT_GRPC_"
	defSvcHTTPPort = "9031"
	defSvcGRPCPort = "7002"
)

var errComputationNotFound = errors.New("computation not found in command line")

type config struct {
	LogLevel   string `env:"AGENT_LOG_LEVEL"          envDefault:"info"`
	JaegerURL  string `env:"COCOS_JAEGER_URL"         envDefault:"http://localhost:14268/api/traces"`
	InstanceID string `env:"AGENT_INSTANCE_ID"        envDefault:""`
	BrokerURL  string `env:"COCOS_MESSAGE_BROKER_URL" envDefault:"nats://localhost:4222"`
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	var cfg config
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("failed to load %s configuration : %s", svcName, err)
	}

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

	tp, err := jaegerclient.NewProvider(ctx, svcName, cfg.JaegerURL, cfg.InstanceID)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to init Jaeger: %s", err))
	}
	defer func() {
		if err := tp.Shutdown(ctx); err != nil {
			logger.Error(fmt.Sprintf("Error shutting down tracer provider: %v", err))
		}
	}()
	tracer := tp.Tracer(svcName)

	pub, err := brokers.NewPublisher(ctx, cfg.BrokerURL)
	if err != nil {
		logger.Error(err.Error())
		return
	}

	svc := newService(ctx, logger, tracer, pub)

	if cmp, err := extractComputationValue(); err == nil {
		if _, err := svc.Run(ctx, cmp); err != nil {
			logger.Fatal(fmt.Sprintf("failed to run computation with err: %s", err))
		}
	} else {
		logger.Warn(fmt.Sprintf("computation not loaded from timeline : %s", err.Error()))
	}

	grpcServerConfig := server.Config{Port: defSvcGRPCPort}
	if err := env.Parse(&grpcServerConfig, env.Options{Prefix: envPrefixGRPC}); err != nil {
		log.Printf("failed to load %s gRPC server configuration : %s", svcName, err.Error())
		return
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

func newService(ctx context.Context, logger mglog.Logger, tracer trace.Tracer, publisher messaging.Publisher) agent.Service {
	svc := agent.New(ctx, logger, publisher)

	svc = api.LoggingMiddleware(svc, logger)
	counter, latency := internal.MakeMetrics(svcName, "api")
	svc = api.MetricsMiddleware(svc, counter, latency)
	svc = tracing.New(svc, tracer)

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
	var computation agent.Computation
	if end == -1 {
		cmpUnescaped = cmdLine[start:]
	}

	escapedCmpStr, err := strconv.Unquote(cmpUnescaped)
	if err != nil {
		return agent.Computation{}, err
	}

	if err := json.Unmarshal([]byte(escapedCmpStr), &computation); err != nil {
		return agent.Computation{}, err
	}
	return computation, nil
}
