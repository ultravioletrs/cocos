package cli

import (
	"log"
	"os"

	"github.com/spf13/cobra"
	agentsdk "github.com/ultravioletrs/agent/pkg/sdk"
)

func NewDatasetsCmd(sdk agentsdk.SDK) *cobra.Command {

	return &cobra.Command{
		Use:   "data",
		Short: "Upload a dataset CSV file",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			datasetFile := args[0]

			log.Println("Uploading dataset CSV:", datasetFile)

			// Read the content of the CSV file into a byte slice
			dataset, err := os.ReadFile(datasetFile)
			if err != nil {
				log.Println("Error reading dataset file:", err)
				return
			}
			response, err := sdk.UploadDataset(dataset)
			if err != nil {
				log.Println("Error uploading dataset:", err)
				return
			}

			log.Println("Response:", response)
		},
	}
}
