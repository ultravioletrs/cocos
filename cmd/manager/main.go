//
// Copyright (c) 2019
// Mainflux
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/digitalocean/go-libvirt"
	"github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/pkg/uuid"
	"github.com/ultravioletrs/agent/agent"
	agentgrpc "github.com/ultravioletrs/agent/pkg/clients/grpc"
	"github.com/ultravioletrs/manager/internal"
	"github.com/ultravioletrs/manager/internal/env"
	jaegerclient "github.com/ultravioletrs/manager/internal/jaeger"
	"github.com/ultravioletrs/manager/internal/server"
	grpcserver "github.com/ultravioletrs/manager/internal/server/grpc"
	httpserver "github.com/ultravioletrs/manager/internal/server/http"
	"github.com/ultravioletrs/manager/manager"
	"github.com/ultravioletrs/manager/manager/api"
	managergrpc "github.com/ultravioletrs/manager/manager/api/grpc"
	httpapi "github.com/ultravioletrs/manager/manager/api/http"
	"github.com/ultravioletrs/manager/manager/qemu"
	"github.com/ultravioletrs/manager/manager/tracing"
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
	LogLevel   string `env:"MANAGER_LOG_LEVEL"   envDefault:"info"`
	JaegerURL  string `env:"MANAGER_JAEGER_URL"  envDefault:"http://localhost:14268/api/traces"`
	InstanceID string `env:"MANAGER_INSTANCE_ID" envDefault:""`
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	g, ctx := errgroup.WithContext(ctx)

	var cfg config
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("failed to load %s configuration : %s", svcName, err)
	}

	logger, err := logger.New(os.Stdout, cfg.LogLevel)
	if err != nil {
		log.Fatalf(err.Error())
	}

	if cfg.InstanceID == "" {
		cfg.InstanceID, err = uuid.New().ID()
		if err != nil {
			logger.Fatal(fmt.Sprintf("Failed to generate instance ID: %s", err))
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

	libvirtConn := initLibvirt(logger)
	defer func() {
		if err := libvirtConn.Disconnect(); err != nil {
			logger.Error(fmt.Sprintf("Error disconnecting from libvirt: %s", err))
		}
	}()

	agentGRPCConfig := agentgrpc.Config{}
	if err := env.Parse(&agentGRPCConfig, env.Options{Prefix: envPrefixAgentGRPC}); err != nil {
		logger.Fatal(fmt.Sprintf("failed to load %s gRPC client configuration : %s", svcName, err))
	}
	agentGRPCClient, agentClient, err := agentgrpc.NewClient(agentGRPCConfig)
	if err != nil {
		logger.Fatal(err.Error())
	}
	defer agentGRPCClient.Close()

	logger.Info("Successfully connected to agent grpc server " + agentGRPCClient.Secure())

	// QEMU
	qemuCfg := qemu.Config{}
	if err := env.Parse(&qemuCfg, env.Options{Prefix: envPrefixQemu}); err != nil {
		logger.Fatal(fmt.Sprintf("failed to load %s QEMU configuration : %s", svcName, err))
	}

	//SVC
	svc := newService(libvirtConn, agentClient, logger, tracer, qemuCfg)

	var httpServerConfig = server.Config{Port: defSvcHTTPPort}
	if err := env.Parse(&httpServerConfig, env.Options{Prefix: envPrefixHTTP}); err != nil {
		logger.Fatal(fmt.Sprintf("failed to load %s gRPC server configuration : %s", svcName, err))
	}
	hs := httpserver.New(ctx, cancel, svcName, httpServerConfig, httpapi.MakeHandler(svc, cfg.InstanceID), logger)

	var grpcServerConfig = server.Config{Port: defSvcGRPCPort}
	if err := env.Parse(&grpcServerConfig, env.Options{Prefix: envPrefixGRPC}); err != nil {
		log.Fatalf("failed to load %s gRPC server configuration : %s", svcName, err.Error())
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

	err = internal.DeleteFilesInDir("tmp/")
	if err != nil {
		logger.Error(fmt.Sprintf("%s", err))
	}
}

func newService(libvirtConn *libvirt.Libvirt, agent agent.AgentServiceClient, logger logger.Logger, tracer trace.Tracer, qemuCfg qemu.Config) manager.Service {
	svc := manager.New(libvirtConn, agent, qemuCfg)

	svc = api.LoggingMiddleware(svc, logger)
	counter, latency := internal.MakeMetrics(svcName, "api")
	svc = api.MetricsMiddleware(svc, counter, latency)
	svc = tracing.New(svc, tracer)

	return svc
}

func initLibvirt(logger logger.Logger) *libvirt.Libvirt {
	// This dials libvirt on the local machine, but you can substitute the first
	// two parameters with "tcp", "<ip address>:<port>" to connect to libvirt on
	// a remote machine.
	c, err := net.DialTimeout("unix", "/var/run/libvirt/libvirt-sock", 2*time.Second)
	if err != nil {
		log.Fatalf("failed to dial libvirt: %v", err)
	}

	l := libvirt.New(c)
	if err := l.Connect(); err != nil {
		log.Fatalf("failed to connect: %v", err)
	}

	v, err := l.Version()
	if err != nil {
		logger.Error(fmt.Sprintf("failed to retrieve libvirt version: %v", err))
	}
	fmt.Println("Version:", v)

	domains, err := l.Domains()
	if err != nil {
		logger.Error(fmt.Sprintf("failed to retrieve domains: %v", err))
	}
	fmt.Println("ID\tName\t\tUUID")
	fmt.Printf("--------------------------------------------------------\n")
	for _, d := range domains {
		fmt.Printf("%d\t%s\t%x\n", d.ID, d.Name, d.UUID)
	}

	return l
}
