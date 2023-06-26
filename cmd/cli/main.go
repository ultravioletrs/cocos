package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/ultravioletrs/agent/cli"
)

var rootCmd = &cobra.Command{
	Use:   "cli-app",
	Short: "CLI application for Computation Service API",
	Run: func(cmd *cobra.Command, args []string) {
		// Display help if no subcommand is provided
		cmd.Help()
	},
}

func init() {
	rootCmd.AddCommand(cli.NewAlgorithmsCmd())
	rootCmd.AddCommand(cli.NewDatasetsCmd())
	rootCmd.AddCommand(cli.NewResultsCmd())

}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
