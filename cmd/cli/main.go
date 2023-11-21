// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"log"
	"os"

	"github.com/absmach/magistrala/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/ultravioletrs/cocos-ai/cli"
	"github.com/ultravioletrs/cocos-ai/internal/env"
	"github.com/ultravioletrs/cocos-ai/pkg/clients/grpc"
	"github.com/ultravioletrs/cocos-ai/pkg/clients/grpc/agent"
	"github.com/ultravioletrs/cocos-ai/pkg/sdk"
)

const (
	svcName            = "cli"
	envPrefixAgentGRPC = "AGENT_GRPC_"
)

type config struct {
	LogLevel string `env:"AGENT_LOG_LEVEL"      envDefault:"info"`
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

	agentGRPCConfig := grpc.Config{}
	if err := env.Parse(&agentGRPCConfig, env.Options{Prefix: envPrefixAgentGRPC}); err != nil {
		logger.Fatal(fmt.Sprintf("failed to load %s gRPC client configuration : %s", svcName, err))
	}

	agentGRPCClient, agentClient, err := agent.NewAgentClient(agentGRPCConfig)
	if err != nil {
		logger.Fatal(err.Error())
	}
	defer agentGRPCClient.Close()

	sdk := sdk.NewAgentSDK(logger, agentClient)

	cli.SetSDK(sdk)

	rootCmd := &cobra.Command{
		Use:   "cocos-cli [command]",
		Short: "CLI application for Computation Service API",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("CLI application for Computation Service API\n\n")
			fmt.Printf("Usage:\n  %s [command]\n\n", cmd.CommandPath())
			fmt.Printf("Available Commands:\n")

			// Filter out "completion" command
			availableCommands := make([]*cobra.Command, 0)
			for _, subCmd := range cmd.Commands() {
				if subCmd.Name() != "completion" {
					availableCommands = append(availableCommands, subCmd)
				}
			}

			for _, subCmd := range availableCommands {
				fmt.Printf("  %-15s%s\n", subCmd.Name(), subCmd.Short)
			}

			fmt.Printf("\nFlags:\n")
			cmd.Flags().VisitAll(func(flag *pflag.Flag) {
				fmt.Printf("  -%s, --%s %s\n", flag.Shorthand, flag.Name, flag.Usage)
			})
			fmt.Printf("\nUse \"%s [command] --help\" for more information about a command.\n", cmd.CommandPath())
		},
	}

	// Root Commands
	rootCmd.AddCommand(cli.NewAlgorithmsCmd(sdk))
	rootCmd.AddCommand(cli.NewDatasetsCmd(sdk))
	rootCmd.AddCommand(cli.NewResultsCmd(sdk))
	rootCmd.AddCommand(cli.NewRunCmd(sdk))
	rootCmd.AddCommand(cli.NewAttestationCmd(sdk))

	if err := rootCmd.Execute(); err != nil {
		logger.Error(fmt.Sprintf("Command execution failed: %s", err))
		return
	}
}
