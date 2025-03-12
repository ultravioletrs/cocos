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

type AgentServer interface {
	Start(cfg agent.AgentConfig, cmp agent.Computation) error
	Stop() error
}

type agentServer struct {
	gs     server.Server
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
	if cfg.Port == "" {
		cfg.Port = defSvcGRPCPort
	}

	agentGrpcServerConfig := server.AgentConfig{
		ServerConfig: server.ServerConfig{
			BaseConfig: server.BaseConfig{
				Host:         as.host,
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

	qp, err := quoteprovider.GetLeveledQuoteProvider()
	if err != nil {
		as.logger.Error(fmt.Sprintf("failed to create quote provider %s", err.Error()))
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())

	as.gs = grpcserver.New(ctx, cancel, svcName, agentGrpcServerConfig, registerAgentServiceServer, as.logger, qp, authSvc)

	go func() {
		err := as.gs.Start()
		if err != nil {
			as.logger.Error(fmt.Sprintf("failed to start grpc server %s", err.Error()))
		}
	}()

	return nil
}

func (as *agentServer) Stop() error {
	return as.gs.Stop()
}
