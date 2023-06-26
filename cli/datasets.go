package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewDatasetsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "upload-dataset",
		Short: "Upload a dataset CSV file",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			datasetFile := args[0]

			fmt.Println("Uploading dataset CSV:", datasetFile)
		},
	}
}
