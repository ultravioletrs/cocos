// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos/agent"
)

func (cli *CLI) NewDatasetsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "data",
		Short:   "Upload a dataset CSV file",
		Example: "data <dataset.csv> <id> <provider>",
		Args:    cobra.ExactArgs(4),
		Run: func(cmd *cobra.Command, args []string) {
			datasetFile := args[0]

			log.Println("Uploading dataset CSV:", datasetFile)

			dataset, err := os.ReadFile(datasetFile)
			if err != nil {
				log.Fatalf("Error reading dataset file: %v", err)
			}

			dataReq := agent.Dataset{
				Dataset:  dataset,
				ID:       args[1],
				Provider: args[2],
			}

			privKeyFile, err := os.ReadFile(args[3])
			if err != nil {
				log.Fatalf("Error reading private key file: %v", err)
			}

			pemBlock, _ := pem.Decode(privKeyFile)

			privKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
			if err != nil {
				log.Fatalf("Error parsing private key: %v", err)
			}

			if err := cli.agentSDK.Data(cmd.Context(), dataReq, privKey); err != nil {
				log.Fatalf("Error uploading dataset: %v", err)
			}

			log.Println("Successfully uploaded dataset")
		},
	}
}
