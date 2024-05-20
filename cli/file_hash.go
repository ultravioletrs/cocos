// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"encoding/hex"
	"log"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/sha3"
)

func (cli *CLI) NewFileHashCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "file-hash",
		Short:   "Compute the sha3-256 hash of a file",
		Example: "file-hash <file>",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			fileName := args[0]

			file, err := os.ReadFile(fileName)
			if err != nil {
				log.Fatalf("Error reading dataset file: %v", err)
			}

			hashBytes := sha3.Sum256(file)

			hash := hex.EncodeToString(hashBytes[:])

			log.Println("Hash of file:", hash)
		},
	}
}
