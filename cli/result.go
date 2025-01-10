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
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := cli.InitializeAgentSDK(cmd); err != nil {
				defer cli.Close()
			}

			if cli.connectErr != nil {

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

			privKey, err := decodeKey(pemBlock)
			if err != nil {
				printError(cmd, "Error decoding private key: %v ❌ ", err)
				return
			}

			resultFile, err := os.Create(filename)
			if err != nil {
				printError(cmd, "Error creating result file: %v ❌ ", err)
				return
			}
			defer resultFile.Close()

			if err = cli.agentSDK.Result(cmd.Context(), privKey, resultFile); err != nil {
				printError(cmd, "Error retrieving computation result: %v ❌ ", err)
				return
			}

			cmd.Println(color.New(color.FgGreen).Sprintf("Computation result retrieved and saved successfully as %s! ✔ ", filename))
		},
	}
}
