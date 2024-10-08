// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"encoding/pem"
	"log"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const resultFilePath = "results.zip"

func (cli *CLI) NewResultsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "result",
		Short:   "Retrieve computation result file",
		Example: "result <private_key_file_path>",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println("⏳ Retrieving computation result file")

			privKeyFile, err := os.ReadFile(args[0])
			if err != nil {
				printError(cmd, "Error reading private key file: %v ❌ ", err)
				return
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

			if err := os.WriteFile(resultFilePath, result, 0o644); err != nil {
				printError(cmd, "Error saving computation result file: %v  ❌ ", err)
				return
			}

			log.Println(color.New(color.FgGreen).Sprint("Computation result retrieved and saved successfully! ✔ "))
		},
	}
}
