// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"

	mgerr "github.com/absmach/magistrala/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos/agent"
)

func (cli *CLI) NewDatasetsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "data",
		Short:   "Upload a dataset CSV file",
		Example: "data <dataset.csv> <private_key_file_path>",
		Args:    cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			datasetFile := args[0]

			log.Println("Uploading dataset CSV:", datasetFile)

			dataset, err := os.ReadFile(datasetFile)
			if err != nil {
				log.Fatalf("Error reading dataset file: %v", err)
			}

			dataReq := agent.Dataset{
				Dataset: dataset,
			}

			privKeyFile, err := os.ReadFile(args[1])
			if err != nil {
				log.Fatalf("Error reading private key file: %v", err)
			}

			pemBlock, _ := pem.Decode(privKeyFile)

			bytes, err := x509.ParsePKCS8PrivateKey(pemBlock.Bytes)
			switch {
			case mgerr.Contains(err, errParsePKC):
				privKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
				if err != nil {
					log.Fatalf("Error parsing private key: %v", err)
				}

				if err := cli.agentSDK.Data(cmd.Context(), dataReq, privKey); err != nil {
					log.Fatalf("Error uploading dataset: %v", err)
				}
			case mgerr.Contains(err, errParseECP):
				privKey, err := x509.ParseECPrivateKey(pemBlock.Bytes)
				if err != nil {
					log.Fatalf("Error parsing private key: %v", err)
				}
				if err := cli.agentSDK.Data(cmd.Context(), dataReq, privKey); err != nil {
					log.Fatalf("Error uploading dataset: %v", err)
				}
			case err == nil:
				ed25519Key, ok := bytes.(ed25519.PrivateKey)
				if !ok {
					log.Fatalf("Error parsing private key: %v", err)
				}

				if err := cli.agentSDK.Data(cmd.Context(), dataReq, ed25519Key); err != nil {
					log.Fatalf("Error uploading dataset: %v", err)
				}
			default:
				log.Fatalf("Error reading private key file: %v", err)
			}

			log.Println("Successfully uploaded dataset")
		},
	}
}
