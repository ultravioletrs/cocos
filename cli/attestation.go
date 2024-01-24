// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"log"
	"os"

	"github.com/spf13/cobra"
)

const attestationFilePath = "attestation.txt"

func (cli *CLI) NewAttestationCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "attestation",
		Short: "Retrieve attestation information",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			log.Println("Checking attestation")

			result, err := cli.agentSDK.Attestation(cmd.Context(), []byte(args[0]))
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
