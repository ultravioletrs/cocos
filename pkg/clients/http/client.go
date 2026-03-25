// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"
	stdtls "crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ultravioletrs/cocos/pkg/atls"
	"github.com/ultravioletrs/cocos/pkg/clients"
	"github.com/ultravioletrs/cocos/pkg/tls"
)

type Client interface {
	Transport() *http.Transport
	Secure() string
	Timeout() time.Duration
}

type client struct {
	transport *http.Transport
	cfg       clients.ClientConfiguration
	security  tls.Security
}

var _ Client = (*client)(nil)

func NewClient(cfg clients.ClientConfiguration) (Client, error) {
	transport, security, err := createTransport(cfg)
	if err != nil {
		return nil, err
	}

	return &client{
		transport: transport,
		cfg:       cfg,
		security:  security,
	}, nil
}

func (c *client) Transport() *http.Transport {
	return c.transport
}

func (c *client) Secure() string {
	return c.security.String()
}

func (c *client) Timeout() time.Duration {
	return c.cfg.Config().Timeout
}

func createTransport(cfg clients.ClientConfiguration) (*http.Transport, tls.Security, error) {
	transport := &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	security := tls.WithoutTLS

	if agcfg, ok := cfg.(*clients.AttestedClientConfig); ok && agcfg.AttestedTLS {
		result, err := tls.LoadATLSConfig(
			agcfg.AttestationPolicy,
			agcfg.ServerCAFile,
			agcfg.ClientCert,
			agcfg.ClientKey,
		)
		if err != nil {
			return nil, security, err
		}

		tlsConfig := result.Config.Clone()
		tlsConfig.MinVersion = stdtls.VersionTLS13
		atlsConfig := &atls.ClientConfig{
			TLSConfig:         tlsConfig,
			VerifyOptions:     atls.VerifyOptionsFromTLSConfig(tlsConfig),
			AttestationPolicy: atls.VerificationPolicyFromEvidenceVerifier(atls.NewEvidenceVerifier(agcfg.AttestationPolicy)),
		}

		transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialNetwork, target := httpDialTarget(network, addr)
			return atls.DialContext(ctx, dialNetwork, target, atlsConfig)
		}
		security = result.Security
	} else {
		conf := cfg.Config()

		result, err := tls.LoadBasicConfig(conf.ServerCAFile, conf.ClientCert, conf.ClientKey)
		if err != nil {
			return nil, security, err
		}

		if result.Security != tls.WithoutTLS {
			transport.TLSClientConfig = result.Config
		}

		security = result.Security
	}

	return transport, security, nil
}

func httpDialTarget(network, addr string) (string, string) {
	if strings.HasPrefix(addr, "unix://") {
		return "unix", strings.TrimPrefix(addr, "unix://")
	}
	if strings.HasPrefix(addr, "/") {
		return "unix", addr
	}
	return network, addr
}
