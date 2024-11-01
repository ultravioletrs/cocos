// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"encoding/pem"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const (
	resultFilePrefix = "results"
	resultFileExt    = ".zip"
	resultfilename   = "results.zip"
)

func (cli *CLI) NewResultsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "result",
		Short:   "Retrieve computation result file",
		Example: "result <private_key_file_path> <optional_file_name.zip>",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if cli.connectErr != nil {
				printError(cmd, "Failed to connect to agent: %v ❌ ", cli.connectErr)
				return
			}

			cmd.Println("⏳ Retrieving computation result file")

			privKeyFile, err := os.ReadFile(args[0])
			if err != nil {
				printError(cmd, "Error reading private key file: %v ❌ ", err)
				return
			}

			filename := resultfilename
			if len(args) > 1 {
				filename = args[1]
			}

			pemBlock, _ := pem.Decode(privKeyFile)

			var result []byte

			privKey, err := decodeKey(pemBlock)
			if err != nil {
				printError(cmd, "Error decoding private key: %v ❌ ", err)
				return
			}
			result, err = cli.agentSDK.Result(cmd.Context(), privKey)
			if err != nil {
				printError(cmd, "Error retrieving computation result: %v ❌ ", err)
				return
			}

			if err := os.WriteFile(filename, result, 0o644); err != nil {
				printError(cmd, "Error saving computation result file: %v  ❌ ", err)
				return
			}

			cmd.Println(color.New(color.FgGreen).Sprintf("Computation result retrieved and saved successfully as %s! ✔ ", filename))
		},
	}
}
