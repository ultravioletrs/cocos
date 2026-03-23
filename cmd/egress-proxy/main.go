// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/caarlos0/env/v11"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/ultravioletrs/cocos/agent/cvms"
	logpb "github.com/ultravioletrs/cocos/agent/log"
	agentlogger "github.com/ultravioletrs/cocos/internal/logger"
	logclient "github.com/ultravioletrs/cocos/pkg/clients/grpc/log"
	"github.com/ultravioletrs/cocos/pkg/egress"
	"golang.org/x/sync/errgroup"
)

const (
	svcName = "egress-proxy"
)

type config struct {
	Level        string `env:"COCOS_LOG_LEVEL" envAlternate:"AGENT_LOG_LEVEL" envDefault:"info"`
	Port         string `env:"COCOS_PROXY_PORT"                envDefault:"3128"`
	LogForwarder string `env:"LOG_FORWARDER_SOCKET"            envDefault:"/run/cocos/log.sock"`
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
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.Level)); err != nil {
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
