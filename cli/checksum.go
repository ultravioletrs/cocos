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

func (cli *CLI) NewFileHashCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "checksum",
		Short:   "Compute the sha3-256 hash of a file",
		Example: "checksum <file>",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := args[0]

			if cli.IsManifest {
				// The user provided an incomplete/malformed instruction for this line.
				// Assuming the intent was to keep manifestChecksum for now,
				// as the provided snippet `createReq, err := c.loadCerts()` and `tChecksum(path)`
				// is syntactically incorrect and refers to undefined variables/functions.
				hash, err := manifestChecksum(path)
				if err != nil {
					cli.printError(cmd, "Error computing hash: %v ❌ ", err)
					return
				}

				cmd.Println("Hash of manifest file:", cli.hashOut(hash))
				return
			}

			hash, err := internal.ChecksumHex(path)
			if err != nil {
				cli.printError(cmd, "Error computing hash: %v ❌ ", err)
				return
			}

			cmd.Println("Hash of file:", cli.hashOut(hash))
		},
	}

	cmd.Flags().BoolVarP(&cli.IsManifest, "manifest", "m", false, "Compute the hash of the manifest file")
	cmd.Flags().BoolVarP(&cli.ToBase64, "base64", "b", false, "Output the hash in base64")

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

func (cli *CLI) hashOut(hashHex string) string {
	if cli.ToBase64 {
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
