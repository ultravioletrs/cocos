// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	mglog "github.com/absmach/supermq/logger"
	"github.com/caarlos0/env/v11"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/ultravioletrs/cocos/pkg/egress"
	"golang.org/x/sync/errgroup"
)

const (
	svcName = "egress-proxy"
)

type config struct {
	Level string `env:"COCOS_LOG_LEVEL" envAlternate:"AGENT_LOG_LEVEL" envDefault:"info"`
	Port  string `env:"COCOS_PROXY_PORT"                envDefault:"3128"`
}

func main() {
	var cfg config
	if err := env.Parse(&cfg); err != nil {
		fmt.Fprintf(os.Stderr, "failed to load configuration: %s\n", err)
		os.Exit(1)
	}

	cmd := &cobra.Command{
		Use:   svcName,
		Short: "Egress Proxy Service",
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cfg)
		},
	}

	pflag.StringVar(&cfg.Level, "log-level", cfg.Level, "Log level")
	pflag.StringVar(&cfg.Port, "port", cfg.Port, "Proxy port")

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func run(cfg config) error {
	logger, err := mglog.New(os.Stdout, cfg.Level)
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)

	proxy := egress.NewProxy(logger, ":"+cfg.Port)

	g.Go(func() error {
		return proxy.Start()
	})

	g.Go(func() error {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		select {
		case s := <-c:
			logger.Info(fmt.Sprintf("received signal %s, stopping", s))
			cancel()
			return proxy.Stop(ctx)
		case <-ctx.Done():
			return nil
		}
	})

	if err := g.Wait(); err != nil {
		return fmt.Errorf("server exit with error: %w", err)
	}

	return nil
}
