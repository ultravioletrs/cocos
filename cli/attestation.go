// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos/agent"
)

const attestationFilePath = "attestation.txt"

func NewAttestationCmd(sdk agent.Service) *cobra.Command {
	return &cobra.Command{
		Use:   "attestation",
		Short: "Retrieve attestation information",
		Run: func(cmd *cobra.Command, args []string) {
			log.Println("Checking attestation")

			result, err := sdk.Attestation(cmd.Context())
			if err != nil {
				log.Fatalf("Error retrieving attestation: %v", err)
			}

			if err = os.WriteFile(attestationFilePath, result, 0o644); err != nil {
				log.Fatalf("Error saving attestation result: %v", err)
			}

			log.Println("Attestation result retrieved and saved successfully!")
		},
	}
}
