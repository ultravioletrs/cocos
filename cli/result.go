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
			log.Println("⏳ Retrieving computation result file")

			privKeyFile, err := os.ReadFile(args[0])
			if err != nil {
				msg := color.New(color.FgRed).Sprintf("Error reading private key file: %v ❌ ", err)
				log.Println(msg)
				return
			}

			pemBlock, _ := pem.Decode(privKeyFile)

			var result []byte

			privKey := decodeKey(pemBlock)
			result, err = cli.agentSDK.Result(cmd.Context(), privKey)
			if err != nil {
				msg := color.New(color.FgRed).Sprintf("Error retrieving computation result: %v ❌ ", err)
				log.Println(msg)
				return
			}

			if err := os.WriteFile(resultFilePath, result, 0o644); err != nil {
				msg := color.New(color.FgRed).Sprintf("Error saving computation result to %s: %v  ❌ ", resultFilePath, err)
				log.Println(msg)
				return
			}

			log.Println(color.New(color.FgGreen).Sprint("Computation result retrieved and saved successfully! ✔ "))
		},
	}
}
