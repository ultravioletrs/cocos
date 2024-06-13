// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"os"

	mgerr "github.com/absmach/magistrala/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos/agent"
)

var (
	errParseECP = errors.New("x509: failed to parse private key (use ParseECPrivateKey instead for this key format)")
	errParsePKC = errors.New("x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)")
)

func (cli *CLI) NewAlgorithmCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "algo",
		Short:   "Upload an algorithm binary",
		Example: "algo <algo_file> <private_key_file_path>",
		Args:    cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			algorithmFile := args[0]

			log.Println("Uploading algorithm binary:", algorithmFile)

			algorithm, err := os.ReadFile(algorithmFile)
			if err != nil {
				log.Fatalf("Error reading algorithm file: %v", err)
			}

			algoReq := agent.Algorithm{
				Algorithm: algorithm,
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
				if err := cli.agentSDK.Algo(cmd.Context(), algoReq, privKey); err != nil {
					log.Fatalf("Error uploading algorithm with error: %v", err)
				}
			case mgerr.Contains(err, errParseECP):
				privKey, err := x509.ParseECPrivateKey(pemBlock.Bytes)
				if err != nil {
					log.Fatalf("Error parsing private key: %v", err)
				}
				if err := cli.agentSDK.Algo(cmd.Context(), algoReq, privKey); err != nil {
					log.Fatalf("Error uploading algorithm with error: %v", err)
				}
			case err == nil:
				ed25519Key, ok := bytes.(ed25519.PrivateKey)
				if !ok {
					log.Fatalf("Error parsing private key: %v", err)
				}

				if err := cli.agentSDK.Algo(cmd.Context(), algoReq, ed25519Key); err != nil {
					log.Fatalf("Error uploading algorithm with error: %v", err)
				}
			default:
				log.Fatalf("Error reading private key file: %v", err)
			}

			log.Println("Successfully uploaded algorithm")
		},
	}
}
