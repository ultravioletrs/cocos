package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewAlgorithmsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "upload-algorithm",
		Short: "Upload an algorithm binary",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			algorithmFile := args[0]

			fmt.Println("Uploading algorithm binary:", algorithmFile)
		},
	}
}
