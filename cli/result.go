// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"

	"github.com/spf13/cobra"
)

const resultFilePath = "result.bin"

func (cli *CLI) NewResultsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "result",
		Short:   "Retrieve computation result file",
		Example: "result <private_key_file_path>",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			log.Println("Retrieving computation result file")

			privKeyFile, err := os.ReadFile(args[0])
			if err != nil {
				log.Fatalf("Error reading private key file: %v", err)
			}

			pemBlock, _ := pem.Decode(privKeyFile)

			var result []byte

			switch pemBlock.Type {
			case rsaKeyType:
				privKey, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
				if err != nil {
					privKey, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
					if err != nil {
						log.Fatalf("Error parsing private key: %v", err)
					}
				}
				result, err = cli.agentSDK.Result(cmd.Context(), privKey)
				if err != nil {
					log.Fatalf("Error retrieving computation result: %v", err)
				}
			case ecdsaKeyType:
				privKey, err := x509.ParseECPrivateKey(pemBlock.Bytes)
				if err != nil {
					log.Fatalf("Error parsing private key: %v", err)
				}
				result, err = cli.agentSDK.Result(cmd.Context(), privKey)
				if err != nil {
					log.Fatalf("Error retrieving computation result: %v", err)
				}
			default:
				log.Fatalf("Error reading private key file: %v", err)
			}
			if err := os.WriteFile(resultFilePath, result, 0o644); err != nil {
				log.Fatalf("Error saving computation result to %s: %v", resultFilePath, err)
			}

			log.Println("Computation result retrieved and saved successfully!")
		},
	}
}
