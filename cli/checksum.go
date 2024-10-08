// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos/internal"
)

func (cli *CLI) NewFileHashCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "checksum",
		Short:   "Compute the sha3-256 hash of a file",
		Example: "checksum <file>",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			path := args[0]

			hash, err := internal.ChecksumHex(path)
			if err != nil {
				cmd.Printf("Error computing hash: %v", err)
				return
			}

			cmd.Println("Hash of file:", hash)
		},
	}
}
