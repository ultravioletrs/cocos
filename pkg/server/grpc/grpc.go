// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
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
	stopWaitTime = 5 * time.Second
)

type Server struct {
	server.BaseServer
	mu                 sync.RWMutex
	server             *grpc.Server
	health             *health.Server
	registerService    serviceRegister
	authSvc            auth.Authenticator
	certProvider       atls.CertificateProvider
	attestedTLSEnabled bool
	started            bool
	stopped            bool
}

type serviceRegister func(srv *grpc.Server)

var _ server.Server = (*Server)(nil)

func New(
	ctx context.Context, cancel context.CancelFunc, name string, config server.ServerConfiguration,
	registerService serviceRegister, logger *slog.Logger, authSvc auth.Authenticator, certProvider atls.CertificateProvider,
) server.Server {
	base := config.GetBaseConfig()
	listenFullAddress := fmt.Sprintf("%s:%s", base.Host, base.Port)

	var attestedTLS bool

	if agentConfig, ok := config.(server.AgentConfig); ok && agentConfig.AttestedTLS {
		if certProvider == nil {
			logger.Error("Failed to create certificate provider")
		} else {
			attestedTLS = true
		}
	}

	return &Server{
		BaseServer: server.BaseServer{
			Ctx:     ctx,
			Cancel:  cancel,
			Name:    name,
			Address: listenFullAddress,
			Config:  config,
			Logger:  logger,
		},
		registerService:    registerService,
		authSvc:            authSvc,
		certProvider:       certProvider,
		attestedTLSEnabled: attestedTLS,
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

	// Add authentication interceptors if auth service is available
	if s.authSvc != nil {
		unary, stream := agentgrpc.NewAuthInterceptor(s.authSvc)
		grpcServerOptions = append(grpcServerOptions, grpc.UnaryInterceptor(unary))
		grpcServerOptions = append(grpcServerOptions, grpc.StreamInterceptor(stream))
	}

	listener, serverOptions, err := s.configureTransport()
	if err != nil {
		return fmt.Errorf("failed to configure transport: %w", err)
	}

	grpcServerOptions = append(grpcServerOptions, serverOptions...)

	// Create and configure server
	s.mu.Lock()
	s.server = grpc.NewServer(grpcServerOptions...)
	s.health = health.NewServer()
	grpchealth.RegisterHealthServer(s.server, s.health)
	s.registerService(s.server)
	s.health.SetServingStatus(s.Name, grpchealth.HealthCheckResponse_SERVING)
	s.mu.Unlock()

	// Start server
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

func (s *Server) configureTransport() (net.Listener, []grpc.ServerOption, error) {
	baseConfig := s.Config.GetBaseConfig()
	network, address := s.listenNetworkAddress(baseConfig)

	if s.shouldUseAttestedTLS() {
		if network == "unix" {
			_ = os.Remove(address)
		}
		listener, err := s.configureAttestedTLS(network, address, baseConfig.Config)
		if err != nil {
			return nil, nil, err
		}
		return listener, []grpc.ServerOption{grpc.Creds(insecure.NewCredentials())}, nil
	}

	if s.shouldUseRegularTLS(baseConfig.Config) {
		if network == "unix" {
			_ = os.Remove(address)
		}
		listener, err := net.Listen(network, address)
		if err != nil {
			return nil, nil, s.listenError(network, address, err)
		}

		creds, err := s.configureRegularTLS(baseConfig.Config)
		if err != nil {
			_ = listener.Close()
			return nil, nil, err
		}
		return listener, []grpc.ServerOption{creds}, nil
	}

	if network == "unix" {
		_ = os.Remove(address)
	}
	listener, err := net.Listen(network, address)
	if err != nil {
		return nil, nil, s.listenError(network, address, err)
	}

	addr := s.Address
	if len(baseConfig.Host) > 0 && baseConfig.Host[0] == '/' {
		addr = baseConfig.Host
	}
	s.Logger.Info(fmt.Sprintf("%s service gRPC server listening at %s without TLS", s.Name, addr))
	return listener, []grpc.ServerOption{grpc.Creds(insecure.NewCredentials())}, nil
}

func (s *Server) shouldUseAttestedTLS() bool {
	return s.attestedTLSEnabled && s.certProvider != nil
}

func (s *Server) shouldUseRegularTLS(config server.Config) bool {
	return config.CertFile != "" || config.KeyFile != ""
}

func (s *Server) configureAttestedTLS(network, address string, config server.Config) (net.Listener, error) {
	tlsConfig, identity, mtls, err := atls.BuildServerTLSConfig(config.CertFile, config.KeyFile, config.ServerCAFile, config.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("failed to setup attested TLS: %w", err)
	}
	tlsConfig.NextProtos = []string{"h2"}

	listener, err := atls.Listen(network, address, &atls.ServerConfig{
		TLSConfig:           tlsConfig,
		Identity:            identity,
		BuildLeafExtensions: s.certProvider.BuildLeafExtensions,
	})
	if err != nil {
		return nil, s.listenError(network, address, err)
	}

	addr := s.Address
	if network == "unix" {
		addr = address
	}
	if mtls {
		s.Logger.Info(fmt.Sprintf("%s service gRPC server listening at %s with Attested mTLS", s.Name, addr))
	} else {
		s.Logger.Info(fmt.Sprintf("%s service gRPC server listening at %s with Attested TLS", s.Name, addr))
	}

	return listener, nil
}

func (s *Server) configureRegularTLS(config server.Config) (grpc.ServerOption, error) {
	tlsSetup, err := server.SetupRegularTLS(config.CertFile, config.KeyFile, config.ServerCAFile, config.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("failed to setup TLS: %w", err)
	}

	if tlsSetup.MTLS {
		mtlsCA := server.BuildMTLSDescription(config.ServerCAFile, config.ClientCAFile)
		s.Logger.Info(fmt.Sprintf("%s service gRPC server listening at %s with TLS/mTLS cert %s , key %s and %s",
			s.Name, s.Address, config.CertFile, config.KeyFile, mtlsCA))
	} else {
		s.Logger.Info(fmt.Sprintf("%s service gRPC server listening at %s with TLS cert %s and key %s",
			s.Name, s.Address, config.CertFile, config.KeyFile))
	}

	return grpc.Creds(credentials.NewTLS(tlsSetup.Config)), nil
}

func (s *Server) listenNetworkAddress(baseConfig server.ServerConfig) (string, string) {
	if len(baseConfig.Host) > 0 && baseConfig.Host[0] == '/' {
		return "unix", baseConfig.Host
	}
	return "tcp", s.Address
}

func (s *Server) listenError(network, address string, err error) error {
	if network == "unix" {
		return fmt.Errorf("failed to listen on Unix socket %s: %w", address, err)
	}
	return fmt.Errorf("failed to listen on port %s: %w", address, err)
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
