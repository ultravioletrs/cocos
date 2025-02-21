// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/go-sev-guest/client"
	agentgrpc "github.com/ultravioletrs/cocos/agent/api/grpc"
	"github.com/ultravioletrs/cocos/agent/auth"
	"github.com/ultravioletrs/cocos/internal/server"
	"github.com/ultravioletrs/cocos/pkg/atls"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
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
	server          *grpc.Server
	registerService serviceRegister
	quoteProvider   client.LeveledQuoteProvider
	authSvc         auth.Authenticator
	health          *health.Server
}

type serviceRegister func(srv *grpc.Server)

var _ server.Server = (*Server)(nil)

func New(ctx context.Context, cancel context.CancelFunc, name string, config server.ServerConfiguration, registerService serviceRegister, logger *slog.Logger, qp client.LeveledQuoteProvider, authSvc auth.Authenticator) server.Server {
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
		quoteProvider:   qp,
		authSvc:         authSvc,
	}
}

func (s *Server) Start() error {
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
	var listener net.Listener

	if agCfg, ok := s.Config.(server.AgentConfig); ok && agCfg.AttestedTLS {
		certificateBytes, privateKeyBytes, err := generateCertificatesForATLS()
		if err != nil {
			return fmt.Errorf("failed to create certificate: %w", err)
		}

		certificate, err := tls.X509KeyPair(certificateBytes, privateKeyBytes)
		if err != nil {
			return fmt.Errorf("falied due to invalid key pair: %w", err)
		}

		tlsConfig := &tls.Config{
			ClientAuth:   tls.NoClientCert,
			Certificates: []tls.Certificate{certificate},
		}

		creds = grpc.Creds(credentials.NewTLS(tlsConfig))

		listener, err = atls.Listen(
			s.Address,
			certificateBytes,
			privateKeyBytes,
		)
		if err != nil {
			return fmt.Errorf("failed to create Listener for aTLS: %w", err)
		}
		s.Logger.Info(fmt.Sprintf("%s service gRPC server listening at %s with Attested TLS", s.Name, s.Address))
	} else {
		c := s.Config.GetBaseConfig()
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

			listener, err = net.Listen("tcp", s.Address)
			if err != nil {
				return fmt.Errorf("failed to listen on port %s: %w", s.Address, err)
			}
		default:
			var err error

			listener, err = net.Listen("tcp", s.Address)
			if err != nil {
				return fmt.Errorf("failed to listen on port %s: %w", s.Address, err)
			}
			s.Logger.Info(fmt.Sprintf("%s service gRPC server listening at %s without TLS", s.Name, s.Address))
		}
	}

	grpcServerOptions = append(grpcServerOptions, creds)

	s.server = grpc.NewServer(grpcServerOptions...)
	s.health = health.NewServer()
	grpchealth.RegisterHealthServer(s.server, s.health)
	s.registerService(s.server)
	s.health.SetServingStatus(s.Name, grpchealth.HealthCheckResponse_SERVING)

	go func() {
		errCh <- s.server.Serve(listener)
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
	defer s.Cancel()
	c := make(chan bool)
	go func() {
		defer close(c)
		s.health.Shutdown()
		s.server.GracefulStop()
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

func generateCertificatesForATLS() ([]byte, []byte, error) {
	curve := elliptic.P256()
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private/public key: %w", err)
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(202403311),
		Subject: pkix.Name{
			Organization:  []string{organization},
			Country:       []string{country},
			Province:      []string{province},
			Locality:      []string{locality},
			StreetAddress: []string{streetAddress},
			PostalCode:    []string{postalCode},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(notAfterYear, notAfterMonth, notAfterDay),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDERBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDERBytes,
	})

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal the private key: %w", err)
	}

	keyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	cert, err := x509.ParseCertificate(certDERBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	pubKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal public key to DER format: %w", err)
	}

	if err := vtpm.ExtendPCR(vtpm.PCR15, pubKeyDER); err != nil {
		return nil, nil, fmt.Errorf("failed to extend vTPM PCR with public key: %w", err)
	}

	return certBytes, keyBytes, nil
}
