// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package server

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

type Server interface {
	Start() error
	Stop() error
}

type ServerConfiguration interface {
	GetBaseConfig() ServerConfig
}

type BaseConfig struct {
	Host         string `env:"HOST"               envDefault:"localhost"`
	Port         string `env:"PORT"               envDefault:"7001"`
	ServerCAFile string `env:"SERVER_CA_CERTS"    envDefault:""`
	CertFile     string `env:"SERVER_CERT"        envDefault:""`
	KeyFile      string `env:"SERVER_KEY"         envDefault:""`
	ClientCAFile string `env:"CLIENT_CA_CERTS"    envDefault:""`
}

type ServerConfig struct {
	BaseConfig
}
type AgentConfig struct {
	ServerConfig
	AttestedTLS bool `env:"ATTESTED_TLS"       envDefault:"false"`
}

type BaseServer struct {
	Ctx      context.Context
	Cancel   context.CancelFunc
	Name     string
	Address  string
	Config   ServerConfiguration
	Logger   *slog.Logger
	Protocol string
}

func (s ServerConfig) GetBaseConfig() ServerConfig {
	return s
}

func (a AgentConfig) GetBaseConfig() ServerConfig {
	return a.ServerConfig
}

func stopAllServer(servers ...Server) error {
	var errs []error
	for _, server := range servers {
		if err := server.Stop(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("encountered errors while stopping servers: %v", errs)
	}

	return nil
}

func StopHandler(ctx context.Context, cancel context.CancelFunc, logger *slog.Logger, svcName string, servers ...Server) error {
	var err error
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGABRT)
	select {
	case sig := <-c:
		defer cancel()
		err = stopAllServer(servers...)
		if err != nil {
			logger.Error(fmt.Sprintf("%s service error during shutdown: %v", svcName, err))
		}
		logger.Info(fmt.Sprintf("%s service shutdown by signal: %s", svcName, sig))
		return err
	case <-ctx.Done():
		return nil
	}
}
