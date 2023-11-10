// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos-ai/pkg/sdk"
)

func NewDatasetsCmd(sdk sdk.SDK) *cobra.Command {
	return &cobra.Command{
		Use:   "data",
		Short: "Upload a dataset CSV file",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			datasetFile := args[0]

			log.Println("Uploading dataset CSV:", datasetFile)

			dataset, err := os.ReadFile(datasetFile)
			if err != nil {
				log.Println("Error reading dataset file:", err)
				return
			}

			response, err := sdk.UploadDataset(context.Background(), dataset)
			if err != nil {
				log.Println("Error uploading dataset:", err)
				return
			}

			log.Println("Response:", response)
		},
	}
}
