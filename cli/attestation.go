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

const attestationFilePath = "attestation.txt"

func NewAttestationCmd(sdk agent.Service) *cobra.Command {
	return &cobra.Command{
		Use:   "attestation",
		Short: "Retrieve attestation information",
		Run: func(cmd *cobra.Command, args []string) {
			log.Println("Checking attestation")

			result, err := sdk.Attestation(context.Background())
			if err != nil {
				log.Println("Error retrieving attestation:", err)
				return
			}

			if err = os.WriteFile(attestationFilePath, result, 0o644); err != nil {
				log.Println("Error saving attestation result:", err)
				return
			}

			log.Println("Attestation result retrieved and saved successfully!")
		},
	}
}
