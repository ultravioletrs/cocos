// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"crypto/x509"
	"log"
	"os"

	"github.com/spf13/cobra"
)

const resultFilePath = "result.bin"

func (cli *CLI) NewResultsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "result",
		Short: "Retrieve computation result file",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			log.Println("Retrieving computation result file")

			privKeyFile, err := os.ReadFile(args[1])
			if err != nil {
				log.Fatalf("Error reading private key file: %v", err)
			}

			privKey, err := x509.ParsePKCS1PrivateKey(privKeyFile)
			if err != nil {
				log.Fatalf("Error parsing private key: %v", err)
			}

			result, err := cli.agentSDK.Result(cmd.Context(), args[0], privKey)
			if err != nil {
				log.Fatalf("Error retrieving computation result: %v", err)
			}

			if err := os.WriteFile(resultFilePath, result, 0o644); err != nil {
				log.Fatalf("Error saving computation result to %s: %v", resultFilePath, err)
			}

			log.Println("Computation result retrieved and saved successfully!")
		},
	}
}
