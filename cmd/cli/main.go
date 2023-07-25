package main

import (
	"fmt"
	"log"
	"os"

	"github.com/mainflux/mainflux/logger"
	"github.com/spf13/cobra"
	"github.com/ultravioletrs/agent/cli"
	"github.com/ultravioletrs/agent/internal/env"
	"github.com/ultravioletrs/agent/pkg/clients/grpc"
	"github.com/ultravioletrs/agent/pkg/sdk"
)

const (
	svcName            = "cli"
	envPrefixAgentGRPC = "AGENT_GRPC_"
)

type config struct {
	LogLevel  string `env:"AGENT_LOG_LEVEL"      envDefault:"info"`
	JaegerURL string `env:"AGENT_JAEGER_URL"     envDefault:""`
}

func main() {
	var cfg config
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("failed to load %s configuration : %s", svcName, err)
	}

	logger, err := logger.New(os.Stdout, cfg.LogLevel)
	if err != nil {
		log.Fatalf("Error creating logger: %s", err)
	}

	userGRPCConfig := grpc.Config{}
	if err := env.Parse(&userGRPCConfig, env.Options{Prefix: envPrefixAgentGRPC}); err != nil {
		logger.Fatal(fmt.Sprintf("failed to load %s gRPC client configuration : %s", svcName, err))
	}

	agentGRPCClient, agentClient, err := grpc.NewClient(userGRPCConfig)
	if err != nil {
		logger.Fatal(err.Error())
	}
	defer agentGRPCClient.Close()

	logger.Info("Successfully connected to agent grpc server " + agentGRPCClient.Secure())

	sdk := sdk.NewAgentSDK(logger, agentClient)

	cli.SetSDK(sdk)

	rootCmd := &cobra.Command{
		Use:   "cli-app",
		Short: "CLI application for Computation Service API",
		Run: func(cmd *cobra.Command, args []string) {
		},
	}

	rootCmd.AddCommand(cli.NewAlgorithmsCmd(sdk))
	rootCmd.AddCommand(cli.NewDatasetsCmd(sdk))
	rootCmd.AddCommand(cli.NewResultsCmd(sdk))
	rootCmd.AddCommand(cli.NewRunCmd(sdk))

	if err := rootCmd.Execute(); err != nil {
		logger.Error(fmt.Sprintf("Command execution failed: %s", err))
		os.Exit(1)
	}
}
