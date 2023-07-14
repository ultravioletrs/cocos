package main

import (
	"log"
	"os"
	"time"

	"github.com/mainflux/mainflux/logger"
	"github.com/spf13/cobra"
	"github.com/ultravioletrs/agent/cli"
	agentsdk "github.com/ultravioletrs/agent/pkg/sdk"
)

const (
	defURL          string        = "localhost:7002"
	defTimeout      time.Duration = time.Second
	agentURLVar     string        = "COCOS_AGENT_URL"
	agentTimeoutVar string        = "COCOS_AGENT_TIMEOUT"
)

func main() {
	agentURL := os.Getenv(agentURLVar)
	if agentURL == "" {
		agentURL = defURL
	}
	agentTimeout := defTimeout
	if at := os.Getenv(agentTimeoutVar); at != "" {
		to, err := time.ParseDuration(at)
		if err != nil {
			log.Fatalf("invalid timeout %s", at)
		}
		agentTimeout = to
	}

	logger, _ := logger.New(os.Stdout, "ERROR")

	sdk, err := agentsdk.NewSDK(agentsdk.Config{
		AgentURL:     agentURL,
		AgentTimeout: agentTimeout,
	}, logger)
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
