// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos-ai/agent"
)

const resultFilePath = "result.bin"

func NewResultsCmd(sdk agent.Service) *cobra.Command {
	return &cobra.Command{
		Use:   "result",
		Short: "Retrieve computation result file",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			log.Println("Retrieving computation result file")

			result, err := sdk.Result(context.Background(), args[0])
			if err != nil {
				log.Println("Error retrieving computation result:", err)
				return
			}

			if err := os.WriteFile(resultFilePath, result, 0o644); err != nil {
				log.Println("Error saving computation result:", err)
				return
			}

			log.Println("Computation result retrieved and saved successfully!")
		},
	}
}
