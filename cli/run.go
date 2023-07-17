package cli

import (
	"encoding/json"
	"log"

	"github.com/spf13/cobra"
	agentsdk "github.com/ultravioletrs/agent/pkg/sdk"
)

func NewRunCmd(sdk agentsdk.SDK) *cobra.Command {
	var computationJSON string

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run a computation",
		Run: func(cmd *cobra.Command, args []string) {
			log.Println("Running computation")

			var computation agentsdk.Computation
			if err := json.Unmarshal([]byte(computationJSON), &computation); err != nil {
				log.Println("Failed to unmarshal computation JSON:", err)
				return
			}

			response, err := sdk.Run(computation)
			if err != nil {
				log.Println("Error running computation:", err)
				return
			}

			log.Println("Response:", response)
		},
	}

	cmd.Flags().StringVar(&computationJSON, "computation", "", "JSON representation of the computation")

	if err := cmd.MarkFlagRequired("computation"); err != nil {
		log.Fatalf("Failed to mark flag as required: %s", err)
	}

	return cmd
}
