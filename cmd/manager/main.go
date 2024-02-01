// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/uuid"
	"github.com/ultravioletrs/cocos/internal"
	"github.com/ultravioletrs/cocos/internal/env"
	"github.com/ultravioletrs/cocos/internal/events"
	jaegerclient "github.com/ultravioletrs/cocos/internal/jaeger"
	"github.com/ultravioletrs/cocos/internal/server"
	grpcserver "github.com/ultravioletrs/cocos/internal/server/grpc"
	httpserver "github.com/ultravioletrs/cocos/internal/server/http"
	"github.com/ultravioletrs/cocos/manager"
	"github.com/ultravioletrs/cocos/manager/api"
	managergrpc "github.com/ultravioletrs/cocos/manager/api/grpc"
	httpapi "github.com/ultravioletrs/cocos/manager/api/http"
	"github.com/ultravioletrs/cocos/manager/qemu"
	"github.com/ultravioletrs/cocos/manager/tracing"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	svcName            = "manager"
	envPrefixHTTP      = "MANAGER_HTTP_"
	envPrefixGRPC      = "MANAGER_GRPC_"
	envPrefixAgentGRPC = "AGENT_GRPC_"
	envPrefixQemu      = "MANAGER_QEMU_"
	defSvcGRPCPort     = "7001"
	defSvcHTTPPort     = "9021"
)

type config struct {
	LogLevel              string `env:"MANAGER_LOG_LEVEL"        envDefault:"info"`
	JaegerURL             string `env:"COCOS_JAEGER_URL"         envDefault:"http://localhost:14268/api/traces"`
	InstanceID            string `env:"MANAGER_INSTANCE_ID"      envDefault:""`
	NotificationServerURL string `env:"COCOS_NOTIFICATION_SERVER_URL" envDefault:"http://localhost:9000"`
	HostIP                string `env:"MANAGER_HOST_IP"          envDefault:"localhost"`
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
			logger.Error(fmt.Sprintf("Failed to generate instance ID: %s", err))
			return
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

	qemuCfg := qemu.Config{}
	if err := env.Parse(&qemuCfg, env.Options{Prefix: envPrefixQemu}); err != nil {
		logger.Error(fmt.Sprintf("failed to load QEMU configuration: %s", err))
		return
	}
	exe, args, err := qemu.ExecutableAndArgs(qemuCfg)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to parse QEMU configuration: %s", err))
		return
	}
	logger.Info(fmt.Sprintf("%s %s", exe, strings.Join(args, " ")))

	svc := newService(logger, tracer, qemuCfg, events.New(svcName, cfg.NotificationServerURL), cfg)

	httpServerConfig := server.Config{Port: defSvcHTTPPort}
	if err := env.Parse(&httpServerConfig, env.Options{Prefix: envPrefixHTTP}); err != nil {
		logger.Error(fmt.Sprintf("failed to load %s gRPC server configuration: %s", svcName, err))
		return
	}
	hs := httpserver.New(ctx, cancel, svcName, httpServerConfig, httpapi.MakeHandler(svc, cfg.InstanceID), logger)

	grpcServerConfig := server.Config{Port: defSvcGRPCPort}
	if err := env.Parse(&grpcServerConfig, env.Options{Prefix: envPrefixGRPC}); err != nil {
		log.Printf("failed to load %s gRPC server configuration: %s", svcName, err.Error())
		return
	}
	registerManagerServiceServer := func(srv *grpc.Server) {
		reflection.Register(srv)
		manager.RegisterManagerServiceServer(srv, managergrpc.NewServer(svc))
	}
	gs := grpcserver.New(ctx, cancel, svcName, grpcServerConfig, registerManagerServiceServer, logger)

	g.Go(func() error {
		return hs.Start()
	})

	g.Go(func() error {
		return gs.Start()
	})

	g.Go(func() error {
		return server.StopHandler(ctx, cancel, logger, svcName, hs, gs)
	})

	if err := g.Wait(); err != nil {
		logger.Error(fmt.Sprintf("%s service terminated: %s", svcName, err))
	}

	err = internal.DeleteFilesInDir(qemuCfg.TmpFileLoc)
	if err != nil {
		logger.Error(err.Error())
	}
}

func newService(logger *slog.Logger, tracer trace.Tracer, qemuCfg qemu.Config, eventSvc events.Service, cfg config) manager.Service {
	svc := manager.New(qemuCfg, logger, eventSvc, cfg.HostIP)

	svc = api.LoggingMiddleware(svc, logger)
	counter, latency := internal.MakeMetrics(svcName, "api")
	svc = api.MetricsMiddleware(svc, counter, latency)
	svc = tracing.New(svc, tracer)

	return svc
}
