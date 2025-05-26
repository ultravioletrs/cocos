// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/absmach/magistrala/pkg/errors"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type security int

const (
	withoutTLS security = iota
	withTLS
	withmTLS
	withaTLS
	withmaTLS
)

const (
	AttestationReportSize = 0x4A0
	WithMATLS             = "with maTLS"
	WithATLS              = "with aTLS"
	WithTLS               = "with TLS"
)

var (
	errGrpcConnect               = errors.New("failed to connect to grpc server")
	errGrpcClose                 = errors.New("failed to close grpc connection")
	errCertificateParse          = errors.New("failed to parse x509 certificate")
	errAttVerification           = errors.New("certificat is not self signed")
	errFailedToLoadClientCertKey = errors.New("failed to load client certificate and key")
	errFailedToLoadRootCA        = errors.New("failed to load root ca file")
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
	cfg    ClientConfiguration
	secure security
}

var _ Client = (*client)(nil)

func NewClient(cfg ClientConfiguration) (Client, error) {
	conn, secure, err := connect(cfg)
	if err != nil {
		return nil, err
	}

	return &client{
		ClientConn: conn,
		cfg:        cfg,
		secure:     secure,
	}, nil
}

func (c *client) Close() error {
	if err := c.ClientConn.Close(); err != nil {
		return errors.Wrap(errGrpcClose, err)
	}
	return nil
}

func (c *client) Secure() string {
	switch c.secure {
	case withTLS:
		return WithTLS
	case withmTLS:
		return "with mTLS"
	case withaTLS:
		return "with aTLS"
	case withmaTLS:
		return WithMATLS
	default:
		return "without TLS"
	}
}

func (c *client) Connection() *grpc.ClientConn {
	return c.ClientConn
}

func connect(cfg ClientConfiguration) (*grpc.ClientConn, security, error) {
	opts := []grpc.DialOption{
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
	}
	secure := withoutTLS

	if agcfg, ok := cfg.(AgentClientConfig); ok && agcfg.AttestedTLS {
		tc, sec, err := setupATLS(agcfg)
		if err != nil {
			return nil, secure, err
		}

		opts = append(opts, grpc.WithTransportCredentials(tc))
		opts = append(opts, grpc.WithContextDialer(CustomDialer))

		secure = sec
	} else {
		conf := cfg.GetBaseConfig()
		transportCreds, sec, err := loadTLSConfig(conf.ServerCAFile, conf.ClientCert, conf.ClientKey)
		if err != nil {
			return nil, secure, err
		}
		opts = append(opts, grpc.WithTransportCredentials(transportCreds))
		secure = sec
	}

	conn, err := grpc.Dial(cfg.GetBaseConfig().URL, opts...)
	if err != nil {
		return nil, secure, errors.Wrap(errGrpcConnect, err)
	}
	return conn, secure, nil
}

func loadTLSConfig(serverCAFile, clientCert, clientKey string) (credentials.TransportCredentials, security, error) {
	tlsConfig := &tls.Config{}
	secure := withoutTLS
	tc := insecure.NewCredentials()

	if serverCAFile != "" {
		rootCA, err := os.ReadFile(serverCAFile)
		if err != nil {
			return nil, secure, errors.Wrap(errFailedToLoadRootCA, err)
		}
		if len(rootCA) > 0 {
			capool := x509.NewCertPool()
			if !capool.AppendCertsFromPEM(rootCA) {
				return nil, secure, fmt.Errorf("failed to append root ca to tls.Config")
			}
			tlsConfig.RootCAs = capool
			secure = withTLS
			tc = credentials.NewTLS(tlsConfig)
		}
	}

	if clientCert != "" || clientKey != "" {
		certificate, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, secure, errors.Wrap(errFailedToLoadClientCertKey, err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
		secure = withmTLS
		tc = credentials.NewTLS(tlsConfig)
	}

	return tc, secure, nil
}
