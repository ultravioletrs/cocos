package cli

import (
	"io/ioutil"
	"log"

	"github.com/spf13/cobra"
	agentsdk "github.com/ultravioletrs/agent/pkg/sdk"
)

func NewResultsCmd(sdk agentsdk.SDK) *cobra.Command {
	return &cobra.Command{
		Use:   "retrieve-result",
		Short: "Retrieve computation result file",
		Run: func(cmd *cobra.Command, args []string) {
			log.Println("Retrieving computation result file")

			result, err := sdk.Result()
			if err != nil {
				log.Println("Error retrieving computation result:", err)
				return
			}
			err = ioutil.WriteFile("result.txt", result, 0644)
			if err != nil {
				log.Println("Error saving computation result:", err)
				return
			}

			log.Println("Computation result retrieved and saved successfully!")
		},
	}
}
