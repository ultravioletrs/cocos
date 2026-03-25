// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"context"
	stdtls "crypto/tls"
	"net"
	"strings"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/ultravioletrs/cocos/pkg/atls"
	"github.com/ultravioletrs/cocos/pkg/clients"
	"github.com/ultravioletrs/cocos/pkg/tls"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	errGrpcConnect = errors.New("failed to connect to grpc server")
	errGrpcClose   = errors.New("failed to close grpc connection")
)

type Client interface {
	Close() error
	Secure() string
	Connection() *grpc.ClientConn
}

type client struct {
	*grpc.ClientConn
	cfg      clients.ClientConfiguration
	security tls.Security
}

var _ Client = (*client)(nil)

func NewClient(cfg clients.ClientConfiguration) (Client, error) {
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

func connect(cfg clients.ClientConfiguration) (*grpc.ClientConn, tls.Security, error) {
	opts := []grpc.DialOption{
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
	}
	security := tls.WithoutTLS

	if agcfg, ok := cfg.(clients.AttestedClientConfig); ok && agcfg.AttestedTLS {
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
		tlsConfig.NextProtos = []string{"h2"}

		atlsConfig := &atls.ClientConfig{
			TLSConfig:         tlsConfig,
			VerifyOptions:     atls.VerifyOptionsFromTLSConfig(tlsConfig),
			AttestationPolicy: atls.VerificationPolicyFromEvidenceVerifier(atls.NewEvidenceVerifier(agcfg.AttestationPolicy)),
		}

		opts = append(opts,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
				network, target := dialTarget(addr)
				conn, err := atls.DialContext(ctx, network, target, atlsConfig)
				if err != nil {
					return nil, err
				}

				return conn, nil
			}),
		)
		security = result.Security
	} else {
		conf := cfg.Config()
		transportCreds, sec, err := loadTLSConfig(conf.ServerCAFile, conf.ClientCert, conf.ClientKey)
		if err != nil {
			return nil, security, err
		}
		opts = append(opts, grpc.WithTransportCredentials(transportCreds))
		security = sec
	}

	conn, err := grpc.NewClient(cfg.Config().URL, opts...)
	if err != nil {
		return nil, security, errors.Wrap(errGrpcConnect, err)
	}
	return conn, security, nil
}

func dialTarget(addr string) (string, string) {
	if strings.HasPrefix(addr, "unix://") {
		return "unix", strings.TrimPrefix(addr, "unix://")
	}
	if strings.HasPrefix(addr, "/") {
		return "unix", addr
	}
	return "tcp", addr
}

func loadTLSConfig(serverCAFile, clientCert, clientKey string) (credentials.TransportCredentials, tls.Security, error) {
	result, err := tls.LoadBasicConfig(serverCAFile, clientCert, clientKey)
	if err != nil {
		return nil, tls.WithoutTLS, err
	}

	if result.Security == tls.WithoutTLS || result.Config == nil {
		return insecure.NewCredentials(), result.Security, nil
	}

	return credentials.NewTLS(result.Config), result.Security, nil
}
