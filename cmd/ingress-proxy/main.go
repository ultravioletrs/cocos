// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/absmach/certs/sdk"
	"github.com/caarlos0/env/v11"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/ultravioletrs/cocos/agent/cvms"
	logpb "github.com/ultravioletrs/cocos/agent/log"
	agentlogger "github.com/ultravioletrs/cocos/internal/logger"
	"github.com/ultravioletrs/cocos/pkg/atls"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/azure"
	logclient "github.com/ultravioletrs/cocos/pkg/clients/grpc/log"
	attestation_client "github.com/ultravioletrs/cocos/pkg/clients/grpc/attestation"
	"github.com/ultravioletrs/cocos/pkg/ingress"
	"golang.org/x/sync/errgroup"
)

const (
	svcName = "ingress-proxy"
)

type config struct {
	LogLevel string `env:"COCOS_LOG_LEVEL" envAlternate:"AGENT_LOG_LEVEL" envDefault:"info"`
	Backend  string `env:"COCOS_INGRESS_BACKEND"           envDefault:"http://localhost:7001"`

	// ATLS Config
	CAUrl         string `env:"AGENT_CVM_CA_URL"             envDefault:""`
	CVMId         string `env:"AGENT_CVM_ID"                 envDefault:""`
	CertsToken    string `env:"AGENT_CERTS_TOKEN"            envDefault:""`
	AgentMaaURL   string `env:"AGENT_MAA_URL"                envDefault:"https://sharedeus2.eus2.attest.azure.net"`
	AgentOSBuild  string `env:"AGENT_OS_BUILD"               envDefault:"UVC"`
	AgentOSDistro string `env:"AGENT_OS_DISTRO"              envDefault:"UVC"`
	AgentOSType   string `env:"AGENT_OS_TYPE"                envDefault:"UVC"`
	LogForwarder  string `env:"LOG_FORWARDER_SOCKET"         envDefault:"/run/cocos/log.sock"`
}

func main() {
	var cfg config
	if err := env.Parse(&cfg); err != nil {
		fmt.Fprintf(os.Stderr, "failed to load configuration: %s\n", err)
		os.Exit(1)
	}

	cmd := &cobra.Command{
		Use:   svcName,
		Short: "Ingress Proxy Service",
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cfg)
		},
	}

	pflag.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "Log level")
	pflag.StringVar(&cfg.Backend, "backend", cfg.Backend, "Backend URL")

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func run(cfg config) error {
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}

	logQueue := make(chan *cvms.ClientStreamMessage, 1000)
	handler := agentlogger.NewProtoHandler(os.Stdout, &slog.HandlerOptions{Level: level}, logQueue)
	logger := slog.New(handler)

	logClient, err := logclient.NewClient(cfg.LogForwarder)
	if err != nil {
		logger.Warn(fmt.Sprintf("failed to connect to log-forwarder: %s. Logs will not be forwarded.", err))
	} else {
		defer logClient.Close()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case msg := <-logQueue:
				if logClient == nil {
					continue
				}
				switch m := msg.Message.(type) {
				case *cvms.ClientStreamMessage_AgentLog:
					err := logClient.SendLog(ctx, &logpb.LogEntry{
						Message:       m.AgentLog.Message,
						ComputationId: m.AgentLog.ComputationId,
						Level:         m.AgentLog.Level,
						Timestamp:     m.AgentLog.Timestamp,
					})
					if err != nil {
						logger.Error("failed to send log", "error", err)
					}
				}
			}
		}
	})

	backendURL, err := url.Parse(cfg.Backend)
	if err != nil {
		return fmt.Errorf("failed to parse backend URL: %w", err)
	}

	// Initialize Certificate Provider
	ccPlatform := attestation.CCPlatform()

	azureConfig := azure.NewEnvConfigFromAgent(
		cfg.AgentOSBuild,
		cfg.AgentOSType,
		cfg.AgentOSDistro,
		cfg.AgentMaaURL,
	)
	azure.InitializeDefaultMAAVars(azureConfig)

	var certProvider atls.CertificateProvider

	if ccPlatform != attestation.NoCC {
		// Create attestation client
		attClient, err := attestation_client.NewClient("/run/cocos/attestation.sock")
		if err != nil {
			return fmt.Errorf("failed to create attestation client: %w", err)
		}
		defer attClient.Close()

		var certsSDK sdk.SDK
		if cfg.CAUrl != "" {
			certsSDK = sdk.NewSDK(sdk.Config{
				CertsURL: cfg.CAUrl,
			})
		}
		certProvider, err = atls.NewProvider(attClient, ccPlatform, cfg.CertsToken, cfg.CVMId, certsSDK)
		if err != nil {
			return fmt.Errorf("failed to create certificate provider: %w", err)
		}
	} else {
		logger.Warn("No Confidential Computing platform detected. ATLS will not be available.")
	}

	// Create proxy server (but don't start it yet - it will be started per-computation)
	_ = ingress.NewProxyServer(logger, backendURL, certProvider)

	// Note: The proxy server will be started dynamically when a computation is initiated
	// via the Manager's ComputationRunReq message. For now, we just keep the service alive.
	logger.Info("ingress-proxy service initialized, waiting for computation requests...")

	g.Go(func() error {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		select {
		case s := <-c:
			logger.Info(fmt.Sprintf("received signal %s, stopping", s))
			cancel()
			return nil
		case <-ctx.Done():
			return nil
		}
	})

	if err := g.Wait(); err != nil {
		return fmt.Errorf("server exit with error: %w", err)
	}

	return nil
}
