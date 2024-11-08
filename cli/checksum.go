// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/internal"
	"golang.org/x/crypto/sha3"
)

var (
	ismanifest bool
	toBase64   bool
)

func (cli *CLI) NewFileHashCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "checksum",
		Short:   "Compute the sha3-256 hash of a file",
		Example: "checksum <file>",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := args[0]

			if ismanifest {
				hash, err := manifestChecksum(path)
				if err != nil {
					printError(cmd, "Error computing hash: %v ❌ ", err)
					return
				}

				cmd.Println("Hash of manifest file:", hashOut(hash))
				return
			}

			hash, err := internal.ChecksumHex(path)
			if err != nil {
				printError(cmd, "Error computing hash: %v ❌ ", err)
				return
			}

			cmd.Println("Hash of file:", hashOut(hash))
		},
	}

	cmd.Flags().BoolVarP(&ismanifest, "manifest", "m", false, "Compute the hash of the manifest file")
	cmd.Flags().BoolVarP(&toBase64, "base64", "b", false, "Output the hash in base64")

	return cmd
}

func manifestChecksum(path string) (string, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	var cmp agent.Computation

	if err := json.Unmarshal(file, &cmp); err != nil {
		return "", err
	}

	jsonBytes, err := json.Marshal(cmp)
	if err != nil {
		return "", err
	}

	sum := sha3.Sum256(jsonBytes)

	return hex.EncodeToString(sum[:]), nil
}

func hashOut(hashHex string) string {
	if toBase64 {
		return hexToBase64(hashHex)
	}

	return hashHex
}

func hexToBase64(hexStr string) string {
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return ""
	}

	return base64.StdEncoding.EncodeToString(decoded)
}
