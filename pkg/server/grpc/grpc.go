// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	agentgrpc "github.com/ultravioletrs/cocos/agent/api/grpc"
	"github.com/ultravioletrs/cocos/agent/auth"
	"github.com/ultravioletrs/cocos/pkg/atls"
	"github.com/ultravioletrs/cocos/pkg/server"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
)

const (
	stopWaitTime  = 5 * time.Second
	organization  = "Ultraviolet"
	country       = "Serbia"
	province      = ""
	locality      = "Belgrade"
	streetAddress = "Bulevar Arsenija Carnojevica 103"
	postalCode    = "11000"
	notAfterYear  = 1
	notAfterMonth = 0
	notAfterDay   = 0
	nonceSize     = 32
)

type Server struct {
	server.BaseServer
	mu              sync.RWMutex
	server          *grpc.Server
	health          *health.Server
	registerService serviceRegister
	authSvc         auth.Authenticator
	caUrl           string
	cvmId           string
	started         bool
	stopped         bool
}

type serviceRegister func(srv *grpc.Server)

var _ server.Server = (*Server)(nil)

func New(ctx context.Context, cancel context.CancelFunc, name string, config server.ServerConfiguration, registerService serviceRegister, logger *slog.Logger, authSvc auth.Authenticator, caUrl string, cvmId string) server.Server {
	base := config.GetBaseConfig()
	listenFullAddress := fmt.Sprintf("%s:%s", base.Host, base.Port)
	return &Server{
		BaseServer: server.BaseServer{
			Ctx:     ctx,
			Cancel:  cancel,
			Name:    name,
			Address: listenFullAddress,
			Config:  config,
			Logger:  logger,
		},
		registerService: registerService,
		authSvc:         authSvc,
		caUrl:           caUrl,
		cvmId:           cvmId,
	}
}

func (s *Server) Start() error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return fmt.Errorf("server already started")
	}
	if s.stopped {
		s.mu.Unlock()
		return fmt.Errorf("server already stopped")
	}
	s.started = true
	s.mu.Unlock()

	errCh := make(chan error)
	grpcServerOptions := []grpc.ServerOption{
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
	}

	if s.authSvc != nil {
		unary, stream := agentgrpc.NewAuthInterceptor(s.authSvc)
		grpcServerOptions = append(grpcServerOptions, grpc.UnaryInterceptor(unary))
		grpcServerOptions = append(grpcServerOptions, grpc.StreamInterceptor(stream))
	}

	creds := grpc.Creds(insecure.NewCredentials())

	c := s.Config.GetBaseConfig()
	if agCfg, ok := s.Config.(server.AgentConfig); ok && agCfg.AttestedTLS {
		tlsConfig := &tls.Config{
			ClientAuth:     tls.NoClientCert,
			GetCertificate: atls.GetCertificate(s.caUrl, s.cvmId),
		}

		mtls, err := server.ConfigureCertificateAuthorities(tlsConfig, c.ServerCAFile, c.ClientCAFile)
		if err != nil {
			return fmt.Errorf("failed to configure certificate authorities: %w", err)
		}

		if mtls {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}

		creds = grpc.Creds(credentials.NewTLS(tlsConfig))

		if mtls {
			s.Logger.Info(fmt.Sprintf("%s service gRPC server listening at %s with Attested mTLS", s.Name, s.Address))
		} else {
			s.Logger.Info(fmt.Sprintf("%s service gRPC server listening at %s with Attested TLS", s.Name, s.Address))
		}
	} else {
		switch {
		case c.CertFile != "" || c.KeyFile != "":
			tlsSetup, err := server.SetupRegularTLS(c.CertFile, c.KeyFile, c.ServerCAFile, c.ClientCAFile)
			if err != nil {
				return fmt.Errorf("failed to setup TLS: %w", err)
			}

			creds = grpc.Creds(credentials.NewTLS(tlsSetup.Config))

			if tlsSetup.MTLS {
				mtlsCA := server.BuildMTLSDescription(c.ServerCAFile, c.ClientCAFile)
				s.Logger.Info(fmt.Sprintf("%s service gRPC server listening at %s with TLS/mTLS cert %s , key %s and %s", s.Name, s.Address, c.CertFile, c.KeyFile, mtlsCA))
			} else {
				s.Logger.Info(fmt.Sprintf("%s service gRPC server listening at %s with TLS cert %s and key %s", s.Name, s.Address, c.CertFile, c.KeyFile))
			}
		default:
			s.Logger.Info(fmt.Sprintf("%s service gRPC server listening at %s without TLS", s.Name, s.Address))
		}
	}

	listener, err := net.Listen("tcp", s.Address)
	if err != nil {
		return fmt.Errorf("failed to listen on port %s: %w", s.Address, err)
	}

	grpcServerOptions = append(grpcServerOptions, creds)

	s.mu.Lock()
	s.server = grpc.NewServer(grpcServerOptions...)
	s.health = health.NewServer()
	grpchealth.RegisterHealthServer(s.server, s.health)
	s.registerService(s.server)
	s.health.SetServingStatus(s.Name, grpchealth.HealthCheckResponse_SERVING)
	s.mu.Unlock()

	go func() {
		s.mu.RLock()
		server := s.server
		s.mu.RUnlock()

		if server != nil {
			errCh <- server.Serve(listener)
		}
	}()

	select {
	case <-s.Ctx.Done():
		return s.Stop()
	case err := <-errCh:
		s.Cancel()
		return err
	}
}

func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stopped {
		return nil
	}
	s.stopped = true

	defer s.Cancel()

	c := make(chan bool)
	go func() {
		defer close(c)
		if s.health != nil {
			s.health.Shutdown()
		}
		if s.server != nil {
			s.server.GracefulStop()
		}
	}()

	select {
	case <-c:
	case <-time.After(stopWaitTime):
	}

	s.Logger.Info(fmt.Sprintf("%s gRPC service shutdown at %s", s.Name, s.Address))
	return nil
}
