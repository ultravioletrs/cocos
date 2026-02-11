// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/absmach/certs/sdk"
	mglog "github.com/absmach/supermq/logger"
	"github.com/caarlos0/env/v11"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/ultravioletrs/cocos/pkg/atls"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/azure"
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
	logger, err := mglog.New(os.Stdout, cfg.LogLevel)
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)

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
