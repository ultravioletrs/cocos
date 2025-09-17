// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package httpclient

import (
	"net/http"
	"time"

	"github.com/ultravioletrs/cocos/pkg/clients"
)

type ClientConfiguration interface {
	Configuration() Config
}

type Config struct {
	URL          string        `env:"URL"             envDefault:"localhost:8080"`
	Timeout      time.Duration `env:"TIMEOUT"         envDefault:"60s"`
	ClientCert   string        `env:"CLIENT_CERT"     envDefault:""`
	ClientKey    string        `env:"CLIENT_KEY"      envDefault:""`
	ServerCAFile string        `env:"SERVER_CA_CERTS" envDefault:""`
}

type AgentClientConfig struct {
	Config

	AttestationPolicy string `env:"ATTESTATION_POLICY" envDefault:""`
	AttestedTLS       bool   `env:"ATTESTED_TLS"       envDefault:"false"`
	ProductName       string `env:"PRODUCT_NAME"       envDefault:"Milan"`
}

type ProxyClientConfig struct {
	Config
}

func (c Config) Configuration() Config {
	return c
}

func (a *AgentClientConfig) Configuration() Config {
	return a.Config
}

func (a ProxyClientConfig) Configuration() Config {
	return a.Config
}

type Client interface {
	Transport() *http.Transport
	Secure() string
	Timeout() time.Duration
}

type client struct {
	transport *http.Transport
	cfg       ClientConfiguration
	security  clients.Security
}

var _ Client = (*client)(nil)

func NewClient(cfg ClientConfiguration) (Client, error) {
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
	return c.cfg.Configuration().Timeout
}

func createTransport(cfg ClientConfiguration) (*http.Transport, clients.Security, error) {
	transport := &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	security := clients.WithoutTLS

	if agcfg, ok := cfg.(*AgentClientConfig); ok && agcfg.AttestedTLS {
		atlsConfig := clients.ATLSConfig{
			BaseConfig: clients.BaseConfig{
				ClientCert:   agcfg.ClientCert,
				ClientKey:    agcfg.ClientKey,
				ServerCAFile: agcfg.ServerCAFile,
			},
			AttestationPolicy: agcfg.AttestationPolicy,
			ProductName:       agcfg.ProductName,
		}

		result, err := clients.LoadATLSConfig(atlsConfig)
		if err != nil {
			return nil, security, err
		}

		transport.TLSClientConfig = result.Config
		security = result.Security
	} else {
		conf := cfg.Configuration()

		result, err := clients.LoadBasicTLSConfig(conf.ServerCAFile, conf.ClientCert, conf.ClientKey)
		if err != nil {
			return nil, security, err
		}

		if result.Security != clients.WithoutTLS {
			transport.TLSClientConfig = result.Config
		}

		security = result.Security
	}

	return transport, security, nil
}
