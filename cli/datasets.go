// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos/agent"
)

func (cli *CLI) NewDatasetsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "data",
		Short:   "Upload a dataset CSV file",
		Example: "data <dataset.csv> <id> <provider>",
		Args:    cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			datasetFile := args[0]

			log.Println("Uploading dataset CSV:", datasetFile)

			dataset, err := os.ReadFile(datasetFile)
			if err != nil {
				log.Fatalf("Error reading dataset file: %v", err)
			}

			dataReq := agent.Dataset{
				Dataset:  dataset,
				ID:       args[1],
				Provider: args[2],
			}

			if err := cli.agentSDK.Data(cmd.Context(), dataReq); err != nil {
				log.Fatalf("Error uploading dataset: %v", err)
			}

			log.Println("Successfully uploaded dataset")
		},
	}
}
