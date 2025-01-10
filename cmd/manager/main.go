// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"net/url"
	"os"
	"strings"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/jaeger"
	"github.com/absmach/magistrala/pkg/prometheus"
	"github.com/absmach/magistrala/pkg/uuid"
	"github.com/caarlos0/env/v11"
	"github.com/ultravioletrs/cocos/internal/server"
	grpcserver "github.com/ultravioletrs/cocos/internal/server/grpc"
	"github.com/ultravioletrs/cocos/manager"
	"github.com/ultravioletrs/cocos/manager/api"
	managergrpc "github.com/ultravioletrs/cocos/manager/api/grpc"
	"github.com/ultravioletrs/cocos/manager/qemu"
	"github.com/ultravioletrs/cocos/manager/tracing"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	svcName          = "manager"
	envPrefixGRPC    = "MANAGER_GRPC_"
	envPrefixQemu    = "MANAGER_QEMU_"
	clientBufferSize = 100
)

type config struct {
	LogLevel                string  `env:"MANAGER_LOG_LEVEL"                  envDefault:"info"`
	JaegerURL               url.URL `env:"COCOS_JAEGER_URL"                   envDefault:"http://localhost:4318"`
	TraceRatio              float64 `env:"COCOS_JAEGER_TRACE_RATIO"           envDefault:"1.0"`
	InstanceID              string  `env:"MANAGER_INSTANCE_ID"                envDefault:""`
	AttestationPolicyBinary string  `env:"MANAGER_ATTESTATION_POLICY_BINARY"  envDefault:"../../build"`
	EosVersion              string  `env:"MANAGER_EOS_VERSION"                envDefault:""`
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
		log.Fatal(err.Error())
	}

	var exitCode int
	defer mglog.ExitWithError(&exitCode)

	if cfg.InstanceID == "" {
		if cfg.InstanceID, err = uuid.New().ID(); err != nil {
			logger.Error(fmt.Sprintf("Failed to generate instance ID: %s", err))
			exitCode = 1
			return
		}
	}

	tp, err := jaeger.NewProvider(ctx, svcName, cfg.JaegerURL, cfg.InstanceID, cfg.TraceRatio)
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
	if err := env.ParseWithOptions(&qemuCfg, env.Options{Prefix: envPrefixQemu}); err != nil {
		logger.Error(fmt.Sprintf("failed to load QEMU configuration: %s", err))
		exitCode = 1
		return
	}
	args := qemuCfg.ConstructQemuArgs()
	logger.Info(strings.Join(args, " "))

	managerGRPCConfig := server.ServerConfig{}
	if err := env.ParseWithOptions(&managerGRPCConfig, env.Options{Prefix: envPrefixGRPC}); err != nil {
		logger.Error(fmt.Sprintf("failed to load %s gRPC client configuration : %s", svcName, err))
		exitCode = 1
		return
	}

	svc, err := newService(logger, tracer, qemuCfg, cfg.AttestationPolicyBinary, cfg.EosVersion)
	if err != nil {
		logger.Error(err.Error())
		exitCode = 1
		return
	}

	registerManagerServiceServer := func(srv *grpc.Server) {
		reflection.Register(srv)
		manager.RegisterManagerServiceServer(srv, managergrpc.NewServer(svc))
	}

	gs := grpcserver.New(ctx, cancel, svcName, managerGRPCConfig, registerManagerServiceServer, logger, nil, nil)

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

func newService(logger *slog.Logger, tracer trace.Tracer, qemuCfg qemu.Config, attestationPolicyPath string, eosVersion string) (manager.Service, error) {
	svc, err := manager.New(qemuCfg, attestationPolicyPath, logger, qemu.NewVM, eosVersion)
	if err != nil {
		return nil, err
	}
	svc = api.LoggingMiddleware(svc, logger)
	counter, latency := prometheus.MakeMetrics(svcName, "api")
	svc = api.MetricsMiddleware(svc, counter, latency)
	svc = tracing.New(svc, tracer)

	return svc, nil
}
