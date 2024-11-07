// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/internal"
	"google.golang.org/grpc/metadata"
)

var decompressDataset bool

func (cli *CLI) NewDatasetsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "data",
		Short:   "Upload a dataset",
		Example: "data <dataset_path> <private_key_file_path>",
		Args:    cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			if cli.connectErr != nil {
				printError(cmd, "Failed to connect to agent: %v ❌ ", cli.connectErr)
				return
			}

			datasetPath := args[0]

			cmd.Println("Uploading dataset:", datasetPath)

			f, err := os.Stat(datasetPath)
			if err != nil {
				printError(cmd, "Error reading dataset file: %v ❌ ", err)
				return
			}

			var dataset *os.File

			if f.IsDir() {
				dataset, err = internal.ZipDirectoryToTempFile(datasetPath)
				if err != nil {
					printError(cmd, "Error zipping dataset directory: %v ❌ ", err)
					return
				}
				defer dataset.Close()
				defer os.Remove(dataset.Name())
			} else {
				dataset, err = os.Open(datasetPath)
				if err != nil {
					printError(cmd, "Error reading dataset file: %v ❌ ", err)
					return
				}
				defer dataset.Close()
			}

			privKeyFile, err := os.ReadFile(args[1])
			if err != nil {
				printError(cmd, "Error reading private key file: %v ❌ ", err)
				return
			}

			pemBlock, _ := pem.Decode(privKeyFile)

			privKey, err := decodeKey(pemBlock)
			if err != nil {
				printError(cmd, "Error decoding private key: %v ❌ ", err)
				return
			}

			ctx := metadata.NewOutgoingContext(cmd.Context(), metadata.New(make(map[string]string)))
			if err := cli.agentSDK.Data(addDatasetMetadata(ctx), dataset, path.Base(datasetPath), privKey); err != nil {
				printError(cmd, "Failed to upload dataset due to error: %v ❌ ", err)
				return
			}

			cmd.Println(color.New(color.FgGreen).Sprint("Successfully uploaded dataset! ✔ "))
		},
	}

	cmd.Flags().BoolVarP(&decompressDataset, "decompress", "d", false, "Decompress the dataset on agent")
	return cmd
}

func decodeKey(b *pem.Block) (interface{}, error) {
	if b == nil {
		return nil, errors.New("error decoding key")
	}
	switch b.Type {
	case rsaKeyType:
		privKey, err := x509.ParsePKCS8PrivateKey(b.Bytes)
		if err != nil {
			privKey, err = x509.ParsePKCS1PrivateKey(b.Bytes)
			if err != nil {
				return nil, err
			}
		}
		return privKey, nil
	case ecdsaKeyType:
		privKey, err := x509.ParseECPrivateKey(b.Bytes)
		if err != nil {
			return nil, err
		}
		return privKey, nil
	default:
		return nil, errors.New("error decoding key")
	}
}

func addDatasetMetadata(ctx context.Context) context.Context {
	return agent.DecompressToContext(ctx, decompressDataset)
}
