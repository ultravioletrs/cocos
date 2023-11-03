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

func NewAlgorithmsCmd(sdk agent.Service) *cobra.Command {
	return &cobra.Command{
		Use:     "algo",
		Short:   "Upload an algorithm binary",
		Example: "algo <algo_file> <id> <provider>",
		Args:    cobra.ExactArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			algorithmFile := args[0]

			log.Println("Uploading algorithm binary:", algorithmFile)

			algorithm, err := os.ReadFile(algorithmFile)
			if err != nil {
				log.Println("Error reading dataset file:", err)
				return
			}

			algoReq := agent.Algorithm{
				Algorithm: algorithm,
				ID:        args[1],
				Provider:  args[2],
			}

			response, err := sdk.Algo(context.Background(), algoReq)
			if err != nil {
				log.Println("Error uploading algorithm:", err)
				return
			}

			log.Println("Successfully uploaded algorithm:", response)
		},
	}
}
