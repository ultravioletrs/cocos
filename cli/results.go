package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewResultsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "retrieve-result",
		Short: "Retrieve computation result file",
		Run: func(cmd *cobra.Command, args []string) {

			fmt.Println("Retrieving computation result file")
		},
	}
}
