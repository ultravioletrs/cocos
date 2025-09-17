// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"time"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/ultravioletrs/cocos/pkg/clients"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	errGrpcConnect = errors.New("failed to connect to grpc server")
	errGrpcClose   = errors.New("failed to close grpc connection")
)

type ClientConfiguration interface {
	GetBaseConfig() BaseConfig
}

type BaseConfig struct {
	URL          string        `env:"URL"             envDefault:"localhost:7001"`
	Timeout      time.Duration `env:"TIMEOUT"         envDefault:"60s"`
	ClientCert   string        `env:"CLIENT_CERT"     envDefault:""`
	ClientKey    string        `env:"CLIENT_KEY"      envDefault:""`
	ServerCAFile string        `env:"SERVER_CA_CERTS" envDefault:""`
}

type AgentClientConfig struct {
	BaseConfig
	AttestationPolicy string `env:"ATTESTATION_POLICY" envDefault:""`
	AttestedTLS       bool   `env:"ATTESTED_TLS"       envDefault:"false"`
	ProductName       string `env:"PRODUCT_NAME"       envDefault:"Milan"`
}

type ManagerClientConfig struct {
	BaseConfig
}

type CVMClientConfig struct {
	BaseConfig
}

func (a BaseConfig) GetBaseConfig() BaseConfig {
	return a
}

func (a AgentClientConfig) GetBaseConfig() BaseConfig {
	return a.BaseConfig
}

func (a CVMClientConfig) GetBaseConfig() BaseConfig {
	return a.BaseConfig
}

type Client interface {
	Close() error
	Secure() string
	Connection() *grpc.ClientConn
}

type client struct {
	*grpc.ClientConn
	cfg      ClientConfiguration
	security clients.Security
}

var _ Client = (*client)(nil)

func NewClient(cfg ClientConfiguration) (Client, error) {
	conn, security, err := connect(cfg)
	if err != nil {
		return nil, err
	}

	return &client{
		ClientConn: conn,
		cfg:        cfg,
		security:   security,
	}, nil
}

func (c *client) Close() error {
	if err := c.ClientConn.Close(); err != nil {
		return errors.Wrap(errGrpcClose, err)
	}
	return nil
}

func (c *client) Secure() string {
	return c.security.String()
}

func (c *client) Connection() *grpc.ClientConn {
	return c.ClientConn
}

func connect(cfg ClientConfiguration) (*grpc.ClientConn, clients.Security, error) {
	opts := []grpc.DialOption{
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
	}
	security := clients.WithoutTLS

	if agcfg, ok := cfg.(AgentClientConfig); ok && agcfg.AttestedTLS {
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

		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(result.Config)))
		security = result.Security
	} else {
		conf := cfg.GetBaseConfig()
		transportCreds, sec, err := loadTLSConfig(conf.ServerCAFile, conf.ClientCert, conf.ClientKey)
		if err != nil {
			return nil, security, err
		}
		opts = append(opts, grpc.WithTransportCredentials(transportCreds))
		security = sec
	}

	conn, err := grpc.Dial(cfg.GetBaseConfig().URL, opts...)
	if err != nil {
		return nil, security, errors.Wrap(errGrpcConnect, err)
	}
	return conn, security, nil
}

func loadTLSConfig(serverCAFile, clientCert, clientKey string) (credentials.TransportCredentials, clients.Security, error) {
	result, err := clients.LoadBasicTLSConfig(serverCAFile, clientCert, clientKey)
	if err != nil {
		return nil, clients.WithoutTLS, err
	}

	if result.Security == clients.WithoutTLS || result.Config == nil {
		return insecure.NewCredentials(), result.Security, nil
	}

	return credentials.NewTLS(result.Config), result.Security, nil
}
