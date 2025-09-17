// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
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

		var mtls bool
		mtls = false

		// Loading Server CA file
		rootCA, err := loadCertFile(c.ServerCAFile)
		if err != nil {
			return fmt.Errorf("failed to load server ca file: %w", err)
		}
		if len(rootCA) > 0 {
			if tlsConfig.RootCAs == nil {
				tlsConfig.RootCAs = x509.NewCertPool()
			}
			if !tlsConfig.RootCAs.AppendCertsFromPEM(rootCA) {
				return fmt.Errorf("failed to append server ca to tls.Config")
			}
			mtls = true
		}

		// Loading Client CA File
		clientCA, err := loadCertFile(c.ClientCAFile)
		if err != nil {
			return fmt.Errorf("failed to load client ca file: %w", err)
		}
		if len(clientCA) > 0 {
			if tlsConfig.ClientCAs == nil {
				tlsConfig.ClientCAs = x509.NewCertPool()
			}
			if !tlsConfig.ClientCAs.AppendCertsFromPEM(clientCA) {
				return fmt.Errorf("failed to append client ca to tls.Config")
			}

			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
			mtls = true
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
			certificate, err := loadX509KeyPair(c.CertFile, c.KeyFile)
			if err != nil {
				return fmt.Errorf("failed to load auth certificates: %w", err)
			}
			tlsConfig := &tls.Config{
				ClientAuth:   tls.NoClientCert,
				Certificates: []tls.Certificate{certificate},
			}

			var mtlsCA string
			// Loading Server CA file
			rootCA, err := loadCertFile(c.ServerCAFile)
			if err != nil {
				return fmt.Errorf("failed to load root ca file: %w", err)
			}
			if len(rootCA) > 0 {
				if tlsConfig.RootCAs == nil {
					tlsConfig.RootCAs = x509.NewCertPool()
				}
				if !tlsConfig.RootCAs.AppendCertsFromPEM(rootCA) {
					return fmt.Errorf("failed to append root ca to tls.Config")
				}
				mtlsCA = fmt.Sprintf("root ca %s", c.ServerCAFile)
			}

			// Loading Client CA File
			clientCA, err := loadCertFile(c.ClientCAFile)
			if err != nil {
				return fmt.Errorf("failed to load client ca file: %w", err)
			}
			if len(clientCA) > 0 {
				if tlsConfig.ClientCAs == nil {
					tlsConfig.ClientCAs = x509.NewCertPool()
				}
				if !tlsConfig.ClientCAs.AppendCertsFromPEM(clientCA) {
					return fmt.Errorf("failed to append client ca to tls.Config")
				}
				mtlsCA = fmt.Sprintf("%s client ca %s", mtlsCA, c.ClientCAFile)
			}
			creds = grpc.Creds(credentials.NewTLS(tlsConfig))
			switch {
			case mtlsCA != "":
				tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
				creds = grpc.Creds(credentials.NewTLS(tlsConfig))
				s.Logger.Info(fmt.Sprintf("%s service gRPC server listening at %s with TLS/mTLS cert %s , key %s and %s", s.Name, s.Address, c.CertFile, c.KeyFile, mtlsCA))
			default:
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

func loadCertFile(certFile string) ([]byte, error) {
	if certFile != "" {
		return readFileOrData(certFile)
	}
	return []byte{}, nil
}

func readFileOrData(input string) ([]byte, error) {
	if len(input) < 1000 && !strings.Contains(input, "\n") {
		data, err := os.ReadFile(input)
		if err == nil {
			return data, nil
		} else {
			return nil, err
		}
	}
	return []byte(input), nil
}

func loadX509KeyPair(certfile, keyfile string) (tls.Certificate, error) {
	cert, err := readFileOrData(certfile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read cert: %v", err)
	}

	key, err := readFileOrData(keyfile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to read key: %v", err)
	}

	return tls.X509KeyPair(cert, key)
}
