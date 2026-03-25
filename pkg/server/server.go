// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"strings"

	smqserver "github.com/absmach/supermq/pkg/server"
)

type Server = smqserver.Server
type Config = smqserver.Config
type BaseServer = smqserver.BaseServer

const StopWaitTime = smqserver.StopWaitTime

// ServerConfiguration is the minimal interface the local server wrappers use.
type ServerConfiguration interface {
	GetBaseConfig() Config
}

// AgentConfig preserves the legacy shape expected by the local HTTP/gRPC server
// wrappers when attested TLS is enabled.
type AgentConfig struct {
	Config
	AttestedTLS bool
}

func (c AgentConfig) GetBaseConfig() Config {
	return c.Config
}

func NewBaseServer(ctx context.Context, cancel context.CancelFunc, name string, config Config, logger *slog.Logger) BaseServer {
	return smqserver.NewBaseServer(ctx, cancel, name, config, logger)
}

// TLSSetupResult contains the result of TLS configuration setup.
type TLSSetupResult struct {
	Config *tls.Config
	MTLS   bool
}

func ReadFileOrData(input string) ([]byte, error) {
	if len(input) < 1000 && !strings.Contains(input, "\n") {
		data, err := os.ReadFile(input)
		if err == nil {
			return data, nil
		}
		return nil, err
	}
	return []byte(input), nil
}

func loadCertFile(certFile string) ([]byte, error) {
	if certFile == "" {
		return []byte{}, nil
	}
	return ReadFileOrData(certFile)
}

func ConfigureCertificateAuthorities(tlsConfig *tls.Config, serverCAFile, clientCAFile string) (bool, error) {
	rootCA, err := loadCertFile(serverCAFile)
	if err != nil {
		return false, fmt.Errorf("failed to load server ca file: %w", err)
	}
	if len(rootCA) > 0 {
		if tlsConfig.RootCAs == nil {
			tlsConfig.RootCAs = x509.NewCertPool()
		}
		if !tlsConfig.RootCAs.AppendCertsFromPEM(rootCA) {
			return false, fmt.Errorf("failed to append server ca to tls.Config")
		}
	}

	clientCA, err := loadCertFile(clientCAFile)
	if err != nil {
		return false, fmt.Errorf("failed to load client ca file: %w", err)
	}
	if len(clientCA) == 0 {
		return false, nil
	}

	if tlsConfig.ClientCAs == nil {
		tlsConfig.ClientCAs = x509.NewCertPool()
	}
	if !tlsConfig.ClientCAs.AppendCertsFromPEM(clientCA) {
		return false, fmt.Errorf("failed to append client ca to tls.Config")
	}

	return true, nil
}

func SetupRegularTLS(certFile, keyFile, serverCAFile, clientCAFile string) (*TLSSetupResult, error) {
	certificate, err := smqserver.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load auth certificates: %w", err)
	}

	tlsConfig := &tls.Config{
		ClientAuth:   tls.NoClientCert,
		Certificates: []tls.Certificate{certificate},
	}

	mtls, err := ConfigureCertificateAuthorities(tlsConfig, serverCAFile, clientCAFile)
	if err != nil {
		return nil, err
	}
	if mtls {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return &TLSSetupResult{Config: tlsConfig, MTLS: mtls}, nil
}

func BuildMTLSDescription(serverCAFile, clientCAFile string) string {
	switch {
	case serverCAFile != "" && clientCAFile != "":
		return fmt.Sprintf("CAs %s, %s", serverCAFile, clientCAFile)
	case serverCAFile != "":
		return fmt.Sprintf("root ca %s", serverCAFile)
	case clientCAFile != "":
		return fmt.Sprintf("client ca %s", clientCAFile)
	default:
		return "no client/server CAs"
	}
}
