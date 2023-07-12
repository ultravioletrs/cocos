package main

import (
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/ultravioletrs/agent/cli"
	agentsdk "github.com/ultravioletrs/agent/pkg/sdk"
)

const (
	defURL      string = "localhost:7002"
	agentURLVar string = "COCOS_AGENT_URL"
)

func main() {
	agentURL := os.Getenv(agentURLVar)
	if agentURL == "" {
		agentURL = defURL
	}

	sdk, err := agentsdk.NewSDK(agentsdk.Config{
		AgentURL: agentURL,
	})
	if err != nil {
		log.Println("Error creating SDK:", err)
		os.Exit(1)
	}

	cli.SetSDK(sdk)

	rootCmd := &cobra.Command{
		Use:   "cli-app",
		Short: "CLI application for Computation Service API",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	rootCmd.AddCommand(cli.NewAlgorithmsCmd(sdk))
	rootCmd.AddCommand(cli.NewDatasetsCmd(sdk))
	rootCmd.AddCommand(cli.NewResultsCmd(sdk))

	if err := rootCmd.Execute(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
