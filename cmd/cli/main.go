// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"syscall"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/caarlos0/env/v11"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/ultravioletrs/cocos/cli"
	"github.com/ultravioletrs/cocos/pkg/clients/grpc"
	"github.com/ultravioletrs/cocos/pkg/clients/grpc/agent"
	"github.com/ultravioletrs/cocos/pkg/sdk"
	cmd "github.com/virtee/sev-snp-measure-go/sevsnpmeasure/cmd"
)

const (
	svcName            = "cli"
	envPrefixAgentGRPC = "AGENT_GRPC_"
	completion         = "completion"
	filePermision      = 0o755
	cocosDirectory     = ".cocos"
)

type config struct {
	LogLevel string `env:"AGENT_LOG_LEVEL" envDefault:"info"`
}

func main() {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-signalChan
		fmt.Println(color.New(color.FgRed).Sprint("\nOperation aborted by user!"))
		os.Exit(2)
	}()

	var cfg config
	if err := env.Parse(&cfg); err != nil {
		log.Fatalf("failed to load %s configuration : %s", svcName, err)
	}

	homePath, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Error fetching user home directory: %v", err)
	}

	directoryCachePath := path.Join(homePath, cocosDirectory)

	if err := os.MkdirAll(directoryCachePath, filePermision); err != nil {
		log.Fatalf("Error while creating directory %s, error: %v", directoryCachePath, err)
	}

	logger, err := mglog.New(os.Stdout, cfg.LogLevel)
	if err != nil {
		log.Fatalf("Error creating logger: %s", err)
	}

	agentGRPCConfig := grpc.Config{}
	if err := env.ParseWithOptions(&agentGRPCConfig, env.Options{Prefix: envPrefixAgentGRPC}); err != nil {
		logger.Error(fmt.Sprintf("failed to load %s gRPC client configuration : %s", svcName, err))
		return
	}

	agentGRPCClient, agentClient, err := agent.NewAgentClient(agentGRPCConfig)
	if err != nil {
		logger.Error(err.Error())
		return
	}
	defer agentGRPCClient.Close()

	agentSDK := sdk.NewAgentSDK(logger, agentClient)

	cliSVC := cli.New(agentSDK)

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

	keysCmd := cliSVC.NewKeysCmd()
	attestationCmd := cliSVC.NewAttestationCmd()
	backendCmd := cliSVC.NewBackendCmd()

	// Agent Commands
	rootCmd.AddCommand(cliSVC.NewAlgorithmCmd())
	rootCmd.AddCommand(cliSVC.NewDatasetsCmd())
	rootCmd.AddCommand(cliSVC.NewResultsCmd())
	rootCmd.AddCommand(attestationCmd)
	rootCmd.AddCommand(cliSVC.NewFileHashCmd())
	rootCmd.AddCommand(backendCmd)
	rootCmd.AddCommand(keysCmd)
	rootCmd.AddCommand(cliSVC.NewCABundleCmd(directoryCachePath))

	// Attestation commands
	attestationCmd.AddCommand(cliSVC.NewGetAttestationCmd())
	attestationCmd.AddCommand(cliSVC.NewValidateAttestationValidationCmd())

	// measure.
	rootCmd.AddCommand(cmd.NewRootCmd())

	// Flags
	keysCmd.PersistentFlags().StringVarP(
		&cli.KeyType,
		"key-type",
		"k",
		"rsa",
		"User Key type",
	)

	// Backend information commands
	backendCmd.AddCommand(cliSVC.NewAddMeasurementCmd())
	backendCmd.AddCommand(cliSVC.NewAddHostDataCmd())

	if err := rootCmd.Execute(); err != nil {
		logger.Error(fmt.Sprintf("Command execution failed: %s", err))
		return
	}
}
