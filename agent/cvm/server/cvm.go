// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package server

import (
	context "context"
	"fmt"
	"log/slog"

	"github.com/ultravioletrs/cocos/agent"
	agentgrpc "github.com/ultravioletrs/cocos/agent/api/grpc"
	"github.com/ultravioletrs/cocos/agent/auth"
	"github.com/ultravioletrs/cocos/internal/server"
	grpcserver "github.com/ultravioletrs/cocos/internal/server/grpc"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	svcName        = "agent"
	defSvcGRPCPort = "7002"
)

type AgentServer struct {
	gs     server.Server
	logger *slog.Logger
	svc    agent.Service
}

func NewServerProvider(logger *slog.Logger, svc agent.Service) *AgentServer {
	return &AgentServer{
		logger: logger,
		svc:    svc,
	}
}

func (as *AgentServer) Start(ctx context.Context, cfg agent.AgentConfig, cmp agent.Computation) error {
	if cfg.Port == "" {
		cfg.Port = defSvcGRPCPort
	}

	agentGrpcServerConfig := server.AgentConfig{
		ServerConfig: server.ServerConfig{
			BaseConfig: server.BaseConfig{
				Host:         cfg.Host,
				Port:         cfg.Port,
				CertFile:     cfg.CertFile,
				KeyFile:      cfg.KeyFile,
				ServerCAFile: cfg.ServerCAFile,
				ClientCAFile: cfg.ClientCAFile,
			},
		},
		AttestedTLS: cfg.AttestedTls,
	}

	registerAgentServiceServer := func(srv *grpc.Server) {
		reflection.Register(srv)
		agent.RegisterAgentServiceServer(srv, agentgrpc.NewServer(as.svc))
	}

	authSvc, err := auth.New(cmp)
	if err != nil {
		as.logger.WithGroup(cmp.ID).Error(fmt.Sprintf("failed to create auth service %s", err.Error()))
		return err
	}

	qp, err := quoteprovider.GetQuoteProvider()
	if err != nil {
		as.logger.Error(fmt.Sprintf("failed to create quote provider %s", err.Error()))
		return err
	}

	ctx, cancel := context.WithCancel(ctx)

	as.gs = grpcserver.New(ctx, cancel, svcName, agentGrpcServerConfig, registerAgentServiceServer, as.logger, qp, authSvc)

	return as.gs.Start()
}

func (as *AgentServer) Stop() error {
	return as.gs.Stop()
}
