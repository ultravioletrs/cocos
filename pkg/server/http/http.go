// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"

	smqserver "github.com/absmach/supermq/pkg/server"
	"github.com/ultravioletrs/cocos/pkg/atls"
	"github.com/ultravioletrs/cocos/pkg/server"
)

const (
	httpProtocol  = "http"
	httpsProtocol = "https"
)

type httpServer struct {
	server.BaseServer

	server             *http.Server
	certProvider       atls.CertificateProvider
	attestedTLSEnabled bool
}

var _ server.Server = (*httpServer)(nil)

func NewServer(
	ctx context.Context, cancel context.CancelFunc, name string, config server.ServerConfiguration,
	handler http.Handler, logger *slog.Logger, certProvider atls.CertificateProvider,
) server.Server {
	baseServer := server.NewBaseServer(ctx, cancel, name, config, logger)
	hserver := &http.Server{Addr: baseServer.Address, Handler: handler}

	var attestedTLS bool

	if agentConfig, ok := config.(server.AgentConfig); ok && agentConfig.AttestedTLS {
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
	return s.Config.GetBaseConfig().CertFile != "" || s.Config.GetBaseConfig().KeyFile != ""
}

func (s *httpServer) startWithAttestedTLS() error {
	tlsConfig := &tls.Config{
		ClientAuth:     tls.NoClientCert,
		GetCertificate: s.certProvider.GetCertificate,
	}

	baseConfig := s.Config.GetBaseConfig()
	mtls, err := server.ConfigureCertificateAuthorities(tlsConfig, baseConfig.ServerCAFile, baseConfig.ClientCAFile)
	if err != nil {
		return fmt.Errorf("failed to configure certificate authorities: %w", err)
	}

	if mtls {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	s.server.TLSConfig = tlsConfig
	s.Protocol = httpsProtocol

	s.logAttestedTLSStart(mtls)
	return s.listenAndServe(true)
}

func (s *httpServer) startWithRegularTLS() error {
	baseConfig := s.Config.GetBaseConfig()
	tlsSetup, err := server.SetupRegularTLS(baseConfig.CertFile, baseConfig.KeyFile, baseConfig.ServerCAFile, baseConfig.ClientCAFile)
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
	baseConfig := s.Config.GetBaseConfig()
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
			cfg := s.Config.GetBaseConfig()
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
