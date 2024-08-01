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
	"github.com/ultravioletrs/cocos/internal"
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
	LogLevel                 string  `env:"MANAGER_LOG_LEVEL"          envDefault:"info"`
	JaegerURL                url.URL `env:"COCOS_JAEGER_URL"           envDefault:"http://localhost:4318"`
	TraceRatio               float64 `env:"MG_JAEGER_TRACE_RATIO"      envDefault:"1.0"`
	InstanceID               string  `env:"MANAGER_INSTANCE_ID"        envDefault:""`
	BackendMeasurementBinary string  `env:"BACKEND_MEASUREMENT_BINARY" envDefault:"../../build"`
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
		if cfg.InstanceID, err = uuid.New().ID(); err != nil {
			logger.Error(fmt.Sprintf("Failed to generate instance ID: %s", err))
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
		return
	}
	args := qemuCfg.ConstructQemuArgs()
	logger.Info(strings.Join(args, " "))

	managerGRPCConfig := grpc.Config{}
	if err := env.ParseWithOptions(&managerGRPCConfig, env.Options{Prefix: envPrefixGRPC}); err != nil {
		logger.Error(fmt.Sprintf("failed to load %s gRPC client configuration : %s", svcName, err))
		return
	}

	managerGRPCClient, managerClient, err := managergrpc.NewManagerClient(managerGRPCConfig)
	if err != nil {
		logger.Error(err.Error())
		return
	}
	defer managerGRPCClient.Close()

	pc, err := managerClient.Process(ctx)
	if err != nil {
		logger.Error(err.Error())
		return
	}

	eventsChan := make(chan *pkgmanager.ClientStreamMessage)
	svc := newService(logger, tracer, qemuCfg, eventsChan, cfg.BackendMeasurementBinary)

	mc := managerapi.NewClient(pc, svc, eventsChan)

	g.Go(func() error {
		return mc.Process(ctx, cancel)
	})

	if err := g.Wait(); err != nil {
		logger.Error(fmt.Sprintf("%s service terminated: %s", svcName, err))
	}

	if err = internal.DeleteFilesInDir(qemuCfg.TmpFileLoc); err != nil {
		logger.Error(err.Error())
	}
}

func newService(logger *slog.Logger, tracer trace.Tracer, qemuCfg qemu.Config, eventsChan chan *pkgmanager.ClientStreamMessage, backendMeasurementPath string) manager.Service {
	svc := manager.New(qemuCfg, backendMeasurementPath, logger, eventsChan, qemu.NewVM)
	go svc.RetrieveAgentEventsLogs()
	svc = api.LoggingMiddleware(svc, logger)
	counter, latency := prometheus.MakeMetrics(svcName, "api")
	svc = api.MetricsMiddleware(svc, counter, latency)
	svc = tracing.New(svc, tracer)

	return svc
}
