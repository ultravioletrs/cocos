// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"encoding/json"
	"log"

	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos-ai/agent"
)

func NewRunCmd(sdk agent.Service) *cobra.Command {
	var computationJSON string

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run a computation",
		Run: func(cmd *cobra.Command, args []string) {
			log.Println("Running computation")

			var computation agent.Computation
			if err := json.Unmarshal([]byte(computationJSON), &computation); err != nil {
				log.Println("Failed to unmarshal computation JSON:", err)
				return
			}

			response, err := sdk.Run(context.Background(), computation)
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
