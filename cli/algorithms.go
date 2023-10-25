// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"log"
	"os"

	"github.com/spf13/cobra"
	agentsdk "github.com/ultravioletrs/agent/pkg/sdk"
)

func NewAlgorithmsCmd(sdk agentsdk.SDK) *cobra.Command {
	return &cobra.Command{
		Use:   "algo",
		Short: "Upload an algorithm binary",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			algorithmFile := args[0]

			log.Println("Uploading algorithm binary:", algorithmFile)

			algorithm, err := os.ReadFile(algorithmFile)
			if err != nil {
				log.Println("Error reading dataset file:", err)
				return
			}

			response, err := sdk.UploadAlgorithm(algorithm)
			if err != nil {
				log.Println("Error uploading algorithm:", err)
				return
			}

			log.Println("Successfully uploaded algorithm:", response)
		},
	}
}
