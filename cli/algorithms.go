// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos/agent"
)

func (cli *CLI) NewAlgorithmsCmd() *cobra.Command {
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
				log.Fatalf("Error reading algorithm file: %v", err)
			}

			algoReq := agent.Algorithm{
				Algorithm: algorithm,
				ID:        args[1],
				Provider:  args[2],
			}

			if err := cli.agentSDK.Algo(cmd.Context(), algoReq); err != nil {
				log.Fatalf("Error uploading algorithm with ID %s and provider %s: %v", algoReq.ID, algoReq.Provider, err)
			}

			log.Println("Successfully uploaded algorithm")
		},
	}
}
