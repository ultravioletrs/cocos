// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/ultravioletrs/cocos/cli"
	"github.com/ultravioletrs/cocos/internal/env"
	managersvc "github.com/ultravioletrs/cocos/manager"
	"github.com/ultravioletrs/cocos/manager/qemu"
	"github.com/ultravioletrs/cocos/pkg/clients/grpc"
	"github.com/ultravioletrs/cocos/pkg/clients/grpc/agent"
	"github.com/ultravioletrs/cocos/pkg/sdk"
)

const (
	svcName              = "cli"
	envPrefixAgentGRPC   = "AGENT_GRPC_"
	envPrefixManagerGRPC = "MANAGER_GRPC_"
	completion           = "completion"
	envPrefixQemu        = "MANAGER_QEMU_"
)

type config struct {
	LogLevel string `env:"AGENT_LOG_LEVEL"               envDefault:"info"`
}

func main() {
	var cfg config
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("failed to load %s configuration : %s", svcName, err)
	}

	logger, err := mglog.New(os.Stdout, cfg.LogLevel)
	if err != nil {
		log.Fatalf("Error creating logger: %s", err)
	}

	agentGRPCConfig := grpc.Config{}
	if err := env.Parse(&agentGRPCConfig, env.Options{Prefix: envPrefixAgentGRPC}); err != nil {
		logger.Error(fmt.Sprintf("failed to load %s gRPC client configuration : %s", svcName, err))
		return
	}

	agentGRPCClient, agentClient, err := agent.NewAgentClient(agentGRPCConfig)
	if err != nil {
		logger.Error(err.Error())
		return
	}
	defer agentGRPCClient.Close()

	qemuCfg := qemu.Config{}
	if err := env.Parse(&qemuCfg, env.Options{Prefix: envPrefixQemu}); err != nil {
		logger.Error(fmt.Sprintf("failed to load QEMU configuration: %s", err))
		return
	}
	exe, args, err := qemu.ExecutableAndArgs(qemuCfg)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to parse QEMU configuration: %s", err))
		return
	}
	logger.Info(fmt.Sprintf("%s %s", exe, strings.Join(args, " ")))

	agentSDK := sdk.NewAgentSDK(logger, agentClient)
	managerSDK := managersvc.New(qemuCfg, logger, make(chan *managersvc.ClientStreamMessage))

	cliSVC := cli.New(agentSDK, managerSDK)

	rootCmd := &cobra.Command{
		Use:   "cocos-cli [command]",
		Short: "CLI application for CoCos Service API",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("CLI application for CoCos Service API\n\n")
			fmt.Printf("Usage:\n  %s [command]\n\n", cmd.CommandPath())
			fmt.Printf("Available Commands:\n")

			// Filter out "completion" command
			availableCommands := make([]*cobra.Command, 0)
			for _, subCmd := range cmd.Commands() {
				if subCmd.Name() != completion {
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

	agentCmd := &cobra.Command{
		Use:   "agent [command]",
		Short: "CLI application for agent Service API",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("CLI application for agent Service API\n\n")
			fmt.Printf("Usage:\n  %s [command]\n\n", cmd.CommandPath())
			fmt.Printf("Available Commands:\n")

			// Filter out "completion" command
			availableCommands := make([]*cobra.Command, 0)
			for _, subCmd := range cmd.Commands() {
				if subCmd.Name() != completion {
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

	managerCmd := &cobra.Command{
		Use:   "manager [command]",
		Short: "CLI application for manager Service API",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("CLI application for manager Service API\n\n")
			fmt.Printf("Usage:\n  %s [command]\n\n", cmd.CommandPath())
			fmt.Printf("Available Commands:\n")

			// Filter out "completion" command
			availableCommands := make([]*cobra.Command, 0)
			for _, subCmd := range cmd.Commands() {
				if subCmd.Name() != completion {
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

	// Root Commands.
	rootCmd.AddCommand(agentCmd)
	rootCmd.AddCommand(managerCmd)

	// agent Commands.
	agentCmd.AddCommand(cliSVC.NewAlgorithmsCmd())
	agentCmd.AddCommand(cliSVC.NewDatasetsCmd())
	agentCmd.AddCommand(cliSVC.NewResultsCmd())
	agentCmd.AddCommand(cliSVC.NewAttestationCmd())

	// manager commands.
	managerCmd.AddCommand(cliSVC.NewRunCmd())

	if err := rootCmd.Execute(); err != nil {
		logger.Error(fmt.Sprintf("Command execution failed: %s", err))
		return
	}
}
