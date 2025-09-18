// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
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

type Client interface {
	Close() error
	Secure() string
	Connection() *grpc.ClientConn
}

type client struct {
	*grpc.ClientConn
	cfg      clients.ClientConfiguration
	security clients.Security
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

func connect(cfg clients.ClientConfiguration) (*grpc.ClientConn, clients.Security, error) {
	opts := []grpc.DialOption{
		grpc.WithStatsHandler(otelgrpc.NewClientHandler()),
	}
	security := clients.WithoutTLS

	if agcfg, ok := cfg.(clients.AttestedClientConfig); ok && agcfg.AttestedTLS {
		result, err := clients.LoadATLSConfig(agcfg)
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
