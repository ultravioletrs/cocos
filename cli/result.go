// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos-ai/pkg/sdk"
)

const resultFilePath = "result.bin"

func NewResultsCmd(sdk sdk.SDK) *cobra.Command {
	return &cobra.Command{
		Use:   "result",
		Short: "Retrieve computation result file",
		Run: func(cmd *cobra.Command, args []string) {
			log.Println("Retrieving computation result file")

			result, err := sdk.Result()
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
