// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/ultravioletrs/cocos/agent"
	agentgrpc "github.com/ultravioletrs/cocos/agent/api/grpc"
	"github.com/ultravioletrs/cocos/agent/auth"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
)

const (
	svcName          = "agent"
	defSvcGRPCSocket = "/run/cocos/agent.sock"
)

type AgentServer interface {
	Start(cfg agent.AgentConfig, cmp agent.Computation) error
	Stop() error
}

type agentServer struct {
	gs     *grpc.Server
	logger *slog.Logger
	svc    agent.Service
	host   string
}

func NewServer(logger *slog.Logger, svc agent.Service, host string) AgentServer {
	return &agentServer{
		logger: logger,
		svc:    svc,
		host:   host,
	}
}

func (as *agentServer) Start(cfg agent.AgentConfig, cmp agent.Computation) error {
	authSvc, err := auth.New(cmp)
	if err != nil {
		as.logger.WithGroup(cmp.ID).Error(fmt.Sprintf("failed to create auth service %s", err.Error()))
		return err
	}

	grpcServerOptions := []grpc.ServerOption{
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
	}

	// Add authentication interceptors
	unary, stream := agentgrpc.NewAuthInterceptor(authSvc)
	grpcServerOptions = append(grpcServerOptions, grpc.UnaryInterceptor(unary))
	grpcServerOptions = append(grpcServerOptions, grpc.StreamInterceptor(stream))

	// Internal Unix socket is pure plaintext HTTP/2; Ingress Proxy handles external aTLS termination
	grpcServerOptions = append(grpcServerOptions, grpc.Creds(insecure.NewCredentials()))

	as.gs = grpc.NewServer(grpcServerOptions...)

	reflection.Register(as.gs)
	agent.RegisterAgentServiceServer(as.gs, agentgrpc.NewServer(as.svc))

	socketPath := as.host
	if socketPath == "" || socketPath == "0.0.0.0" {
		socketPath = defSvcGRPCSocket
	}

	var listener net.Listener
	if socketPath[0] == '/' || socketPath[0] == '.' {
		// Remove existing socket file if it exists
		_ = os.Remove(socketPath)
		listener, err = net.Listen("unix", socketPath)
	} else {
		listener, err = net.Listen("tcp", socketPath)
	}

	if err != nil {
		as.logger.Error(fmt.Sprintf("failed to listen on %s: %s", socketPath, err))
		return err
	}

	as.logger.Info(fmt.Sprintf("agent service gRPC server listening at %s without TLS", socketPath))

	go func() {
		err := as.gs.Serve(listener)
		if err != nil && err != grpc.ErrServerStopped {
			as.logger.Error(fmt.Sprintf("failed to start grpc server %s", err.Error()))
		}
	}()

	return nil
}

func (as *agentServer) Stop() error {
	if as.gs != nil {
		as.gs.GracefulStop()
	}
	return nil
}
