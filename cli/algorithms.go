package cli

import (
	"log"

	"github.com/spf13/cobra"
	agentsdk "github.com/ultravioletrs/agent/pkg/sdk"
)

func NewAlgorithmsCmd(sdk agentsdk.SDK) *cobra.Command {
	return &cobra.Command{
		Use:   "algorithm",
		Short: "Upload an algorithm binary",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			algorithmFile := args[0]

			log.Println("Uploading algorithm binary:", algorithmFile)

			response, err := sdk.UploadAlgorithm([]byte(algorithmFile))
			if err != nil {
				log.Println("Error uploading algorithm:", err)
				return
			}

			log.Println("Response:", response)
		},
	}
}
