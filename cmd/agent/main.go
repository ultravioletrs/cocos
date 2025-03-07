// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/prometheus"
	"github.com/caarlos0/env/v11"
	"github.com/google/go-sev-guest/client"
	"github.com/stretchr/testify/mock"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/agent/api"
	"github.com/ultravioletrs/cocos/agent/cvms"
	cvmsapi "github.com/ultravioletrs/cocos/agent/cvms/api/grpc"
	"github.com/ultravioletrs/cocos/agent/cvms/server"
	"github.com/ultravioletrs/cocos/agent/events"
	agentlogger "github.com/ultravioletrs/cocos/internal/logger"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider/mocks"
	pkggrpc "github.com/ultravioletrs/cocos/pkg/clients/grpc"
	cvmsgrpc "github.com/ultravioletrs/cocos/pkg/clients/grpc/cvm"
	"golang.org/x/sync/errgroup"
)

const (
	svcName          = "agent"
	defSvcGRPCPort   = "7002"
	retryInterval    = 5 * time.Second
	envPrefixCVMGRPC = "AGENT_CVM_GRPC_"
	storageDir       = "/var/lib/cocos/agent"
)

type config struct {
	LogLevel string `env:"AGENT_LOG_LEVEL" envDefault:"debug"`
	Vmpl     int    `env:"AGENT_VMPL" envDefault:"2"`
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	var cfg config
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("failed to load %s configuration : %s", svcName, err)
	}

	var exitCode int
	defer mglog.ExitWithError(&exitCode)

	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		log.Println(err)
		exitCode = 1
		return
	}

	eventsLogsQueue := make(chan *cvms.ClientStreamMessage, 1000)

	handler := agentlogger.NewProtoHandler(os.Stdout, &slog.HandlerOptions{Level: level}, eventsLogsQueue)
	logger := slog.New(handler)

	eventSvc, err := events.New(svcName, eventsLogsQueue)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create events service %s", err.Error()))
		exitCode = 1
		return
	}

	var qp client.LeveledQuoteProvider

	if !sevGuesDeviceExists() {
		logger.Info("SEV-SNP device not found")
		qpMock := new(mocks.LeveledQuoteProvider)
		qpMock.On("GetRawQuoteAtLevel", mock.Anything, mock.Anything).Return([]uint8{}, errors.New("SEV-SNP device not found"))
		qp = qpMock
	} else {
		qp, err = quoteprovider.GetLeveledQuoteProvider()
		if err != nil {
			logger.Error(fmt.Sprintf("failed to create quote provider %s", err.Error()))
			exitCode = 1
			return
		}
	}

	cvmGrpcConfig := pkggrpc.CVMClientConfig{}
	if err := env.ParseWithOptions(&cvmGrpcConfig, env.Options{Prefix: envPrefixCVMGRPC}); err != nil {
		logger.Error(fmt.Sprintf("failed to load %s gRPC client configuration : %s", svcName, err))
		exitCode = 1
		return
	}

	cvmGRPCClient, cvmsClient, err := cvmsgrpc.NewCVMClient(cvmGrpcConfig)
	if err != nil {
		logger.Error(err.Error())
		exitCode = 1
		return
	}
	defer cvmGRPCClient.Close()

	reconnectFn := func(ctx context.Context) (cvms.Service_ProcessClient, error) {
		_, newClient, err := cvmsgrpc.NewCVMClient(cvmGrpcConfig)
		if err != nil {
			return nil, err
		}
		// Don't defer close here as we want to keep the connection open

		return newClient.Process(ctx)
	}

	pc, err := cvmsClient.Process(ctx)
	if err != nil {
		logger.Error(err.Error())
		exitCode = 1
		return
	}

	if cfg.Vmpl < 0 || cfg.Vmpl > 3 {
		logger.Error("vmpl level must be in a range [0, 3]")
		exitCode = 1
		return
	}

	svc := newService(ctx, logger, eventSvc, qp, cfg.Vmpl)

	if err := os.MkdirAll(storageDir, 0o755); err != nil {
		logger.Error(fmt.Sprintf("failed to create storage directory: %s", err))
		exitCode = 1
		return
	}

	mc, err := cvmsapi.NewClient(pc, svc, eventsLogsQueue, logger, server.NewServer(logger, svc), storageDir, reconnectFn)
	if err != nil {
		logger.Error(err.Error())
		exitCode = 1
		return
	}

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

func newService(ctx context.Context, logger *slog.Logger, eventSvc events.Service, qp client.LeveledQuoteProvider, vmpl int) agent.Service {
	svc := agent.New(ctx, logger, eventSvc, qp, vmpl)

	svc = api.LoggingMiddleware(svc, logger)
	counter, latency := prometheus.MakeMetrics(svcName, "api")
	svc = api.MetricsMiddleware(svc, counter, latency)

	return svc
}

func sevGuesDeviceExists() bool {
	d, err := client.OpenDevice()
	if err != nil {
		return false
	}
	d.Close()
	return true
}
