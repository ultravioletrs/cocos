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
	"os/signal"
	"strings"
	"syscall"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/jaeger"
	"github.com/absmach/magistrala/pkg/prometheus"
	"github.com/absmach/magistrala/pkg/uuid"
	"github.com/caarlos0/env/v11"
	"github.com/ultravioletrs/cocos/manager"
	"github.com/ultravioletrs/cocos/manager/api"
	managerapi "github.com/ultravioletrs/cocos/manager/api/grpc"
	"github.com/ultravioletrs/cocos/manager/qemu"
	"github.com/ultravioletrs/cocos/manager/tracing"
	"github.com/ultravioletrs/cocos/pkg/clients/grpc"
	managergrpc "github.com/ultravioletrs/cocos/pkg/clients/grpc/manager"
	pkgmanager "github.com/ultravioletrs/cocos/pkg/manager"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
)

const (
	svcName       = "manager"
	envPrefixGRPC = "MANAGER_GRPC_"
	envPrefixQemu = "MANAGER_QEMU_"
)

type config struct {
	LogLevel                 string  `env:"MANAGER_LOG_LEVEL"                  envDefault:"info"`
	JaegerURL                url.URL `env:"COCOS_JAEGER_URL"                   envDefault:"http://localhost:4318"`
	TraceRatio               float64 `env:"COCOS_JAEGER_TRACE_RATIO"           envDefault:"1.0"`
	InstanceID               string  `env:"MANAGER_INSTANCE_ID"                envDefault:""`
	BackendMeasurementBinary string  `env:"MANAGER_BACKEND_MEASUREMENT_BINARY" envDefault:"../../build"`
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

	managerGRPCConfig := grpc.Config{}
	if err := env.ParseWithOptions(&managerGRPCConfig, env.Options{Prefix: envPrefixGRPC}); err != nil {
		logger.Error(fmt.Sprintf("failed to load %s gRPC client configuration : %s", svcName, err))
		exitCode = 1
		return
	}

	managerGRPCClient, managerClient, err := managergrpc.NewManagerClient(managerGRPCConfig)
	if err != nil {
		logger.Error(err.Error())
		exitCode = 1
		return
	}
	defer managerGRPCClient.Close()

	pc, err := managerClient.Process(ctx)
	if err != nil {
		logger.Error(err.Error())
		exitCode = 1
		return
	}

	eventsChan := make(chan *pkgmanager.ClientStreamMessage)
	svc, err := newService(logger, tracer, qemuCfg, eventsChan, cfg.BackendMeasurementBinary)
	if err != nil {
		logger.Error(err.Error())
		exitCode = 1
		return
	}

	mc := managerapi.NewClient(pc, svc, eventsChan, logger)

	g.Go(func() error {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(ch)

		select {
		case <-ch:
			logger.Info("Received signal, shutting down...")
			cancel()
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	g.Go(func() error {
		return mc.Process(ctx, cancel)
	})

	if err := g.Wait(); err != nil {
		logger.Error(fmt.Sprintf("%s service terminated: %s", svcName, err))
	}
}

func newService(logger *slog.Logger, tracer trace.Tracer, qemuCfg qemu.Config, eventsChan chan *pkgmanager.ClientStreamMessage, backendMeasurementPath string) (manager.Service, error) {
	svc, err := manager.New(qemuCfg, backendMeasurementPath, logger, eventsChan, qemu.NewVM)
	if err != nil {
		return nil, err
	}
	go svc.RetrieveAgentEventsLogs()
	svc = api.LoggingMiddleware(svc, logger)
	counter, latency := prometheus.MakeMetrics(svcName, "api")
	svc = api.MetricsMiddleware(svc, counter, latency)
	svc = tracing.New(svc, tracer)

	return svc, nil
}
