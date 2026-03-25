// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"

	smqserver "github.com/absmach/supermq/pkg/server"
	"github.com/ultravioletrs/cocos/pkg/atls"
	cocosserver "github.com/ultravioletrs/cocos/pkg/server"
)

const (
	httpProtocol  = "http"
	httpsProtocol = "https"
)

type httpServer struct {
	cocosserver.BaseServer

	server             *http.Server
	certProvider       atls.CertificateProvider
	attestedTLSEnabled bool
}

var _ cocosserver.Server = (*httpServer)(nil)

func NewServer(
	ctx context.Context, cancel context.CancelFunc, name string, config cocosserver.ServerConfiguration,
	handler http.Handler, logger *slog.Logger, certProvider atls.CertificateProvider,
) cocosserver.Server {
	baseConfig := config.GetBaseConfig()
	baseServer := cocosserver.NewBaseServer(ctx, cancel, name, baseConfig, logger)
	hserver := &http.Server{Addr: baseServer.Address, Handler: handler}

	var attestedTLS bool

	if agentConfig, ok := config.(cocosserver.AgentConfig); ok && agentConfig.AttestedTLS {
		if certProvider == nil {
			logger.Error("Failed to create certificate provider")
		} else {
			attestedTLS = true
		}
	}

	return &httpServer{
		BaseServer:         baseServer,
		server:             hserver,
		certProvider:       certProvider,
		attestedTLSEnabled: attestedTLS,
	}
}

func (s *httpServer) Start() error {
	s.Protocol = httpProtocol

	if s.shouldUseAttestedTLS() {
		return s.startWithAttestedTLS()
	}

	if s.shouldUseRegularTLS() {
		return s.startWithRegularTLS()
	}

	return s.startWithoutTLS()
}

func (s *httpServer) Stop() error {
	defer s.Cancel()

	ctx, cancel := context.WithTimeout(context.Background(), smqserver.StopWaitTime)
	defer cancel()

	if err := s.server.Shutdown(ctx); err != nil {
		s.Logger.Error(fmt.Sprintf(
			"%s service %s server error occurred during shutdown at %s: %s", s.Name, s.Protocol, s.Address, err))
		return fmt.Errorf("%s service %s server error occurred during shutdown at %s: %w", s.Name, s.Protocol, s.Address, err)
	}

	s.Logger.Info(fmt.Sprintf("%s %s service shutdown of http at %s", s.Name, s.Protocol, s.Address))
	return nil
}

func (s *httpServer) shouldUseAttestedTLS() bool {
	return s.attestedTLSEnabled && s.certProvider != nil
}

func (s *httpServer) shouldUseRegularTLS() bool {
	return s.Config.CertFile != "" || s.Config.KeyFile != ""
}

func (s *httpServer) startWithAttestedTLS() error {
	baseConfig := s.Config
	tlsConfig, identity, mtls, err := atls.BuildServerTLSConfig(baseConfig.CertFile, baseConfig.KeyFile, baseConfig.ServerCAFile, baseConfig.ClientCAFile)
	if err != nil {
		return fmt.Errorf("failed to setup attested TLS: %w", err)
	}
	tlsConfig.NextProtos = []string{"h2", "http/1.1"}

	s.server.TLSConfig = tlsConfig
	s.Protocol = httpsProtocol

	s.logAttestedTLSStart(mtls)
	listener, err := s.attestedListener(tlsConfig, identity)
	if err != nil {
		return err
	}
	return s.serveListener(listener)
}

func (s *httpServer) startWithRegularTLS() error {
	baseConfig := s.Config
	tlsSetup, err := cocosserver.SetupRegularTLS(baseConfig.CertFile, baseConfig.KeyFile, baseConfig.ServerCAFile, baseConfig.ClientCAFile)
	if err != nil {
		return fmt.Errorf("failed to setup TLS: %w", err)
	}

	s.server.TLSConfig = tlsSetup.Config
	s.Protocol = httpsProtocol

	s.logRegularTLSStart(tlsSetup.MTLS)
	return s.listenAndServe(true)
}

func (s *httpServer) startWithoutTLS() error {
	s.Logger.Info(fmt.Sprintf("%s service %s server listening at %s without TLS", s.Name, s.Protocol, s.Address))
	return s.listenAndServe(false)
}

func (s *httpServer) logAttestedTLSStart(mtls bool) {
	if mtls {
		s.Logger.Info(fmt.Sprintf("%s service %s server listening at %s with Attested mTLS", s.Name, s.Protocol, s.Address))
	} else {
		s.Logger.Info(fmt.Sprintf("%s service %s server listening at %s with Attested TLS", s.Name, s.Protocol, s.Address))
	}
}

func (s *httpServer) logRegularTLSStart(mtls bool) {
	baseConfig := s.Config
	if mtls {
		s.Logger.Info(fmt.Sprintf(
			"%s service %s server listening at %s with TLS/mTLS cert %s , key %s and CAs %s, %s",
			s.Name, s.Protocol, s.Address, baseConfig.CertFile, baseConfig.KeyFile,
			baseConfig.ServerCAFile, baseConfig.ClientCAFile))
	} else {
		s.Logger.Info(fmt.Sprintf("%s service %s server listening at %s with TLS cert %s and key %s",
			s.Name, s.Protocol, s.Address, baseConfig.CertFile, baseConfig.KeyFile))
	}
}

func (s *httpServer) listenAndServe(useTLS bool) error {
	errCh := make(chan error, 1)

	go func() {
		if useTLS {
			cfg := s.Config
			errCh <- s.server.ListenAndServeTLS(cfg.CertFile, cfg.KeyFile)
		} else {
			errCh <- s.server.ListenAndServe()
		}
	}()

	select {
	case <-s.Ctx.Done():
		return s.Stop()
	case err := <-errCh:
		return err
	}
}

func (s *httpServer) serveListener(listener net.Listener) error {
	errCh := make(chan error, 1)

	go func() {
		errCh <- s.server.Serve(listener)
	}()

	select {
	case <-s.Ctx.Done():
		return s.Stop()
	case err := <-errCh:
		return err
	}
}

func (s *httpServer) attestedListener(tlsConfig *tls.Config, identity tls.Certificate) (net.Listener, error) {
	baseConfig := s.Config
	network, address := s.listenNetworkAddress(baseConfig)
	if network == "unix" {
		_ = os.Remove(address)
	}
	listener, err := atls.Listen(network, address, &atls.ServerConfig{
		TLSConfig:           tlsConfig,
		Identity:            identity,
		BuildLeafExtensions: s.certProvider.BuildLeafExtensions,
	})
	if err != nil {
		if network == "unix" {
			return nil, fmt.Errorf("failed to listen on Unix socket %s: %w", address, err)
		}
		return nil, fmt.Errorf("failed to listen on port %s: %w", address, err)
	}
	return listener, nil
}

func (s *httpServer) listenNetworkAddress(baseConfig cocosserver.Config) (string, string) {
	if len(baseConfig.Host) > 0 && baseConfig.Host[0] == '/' {
		return "unix", baseConfig.Host
	}
	return "tcp", s.Address
}
