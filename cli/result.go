// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"encoding/pem"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const resultFilename = "results.zip"

func (cli *CLI) NewResultsCmd() *cobra.Command {
	var outputDir string
	var filename string

	cmd := &cobra.Command{
		Use:     "result <private_key_file_path>",
		Short:   "Retrieve computation result file",
		Example: "result <private_key_file_path> --filename my_results.zip --output-dir /path/to/directory",
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

			// Construct full output path
			var outputPath string
			if outputDir != "" {
				// Create output directory if it doesn't exist
				if err := os.MkdirAll(outputDir, 0755); err != nil {
					printError(cmd, "Error creating output directory: %v ❌ ", err)
					return
				}
				outputPath = filepath.Join(outputDir, filename)
			} else {
				outputPath = filename
			}

			// Get absolute path for display
			absPath, err := filepath.Abs(outputPath)
			if err != nil {
				absPath = outputPath
			}

			pemBlock, _ := pem.Decode(privKeyFile)

			privKey, err := decodeKey(pemBlock)
			if err != nil {
				printError(cmd, "Error decoding private key: %v ❌ ", err)
				return
			}

			resultFile, err := os.Create(outputPath)
			if err != nil {
				printError(cmd, "Error creating result file: %v ❌ ", err)
				return
			}
			defer resultFile.Close()

			if err = cli.agentSDK.Result(cmd.Context(), privKey, resultFile); err != nil {
				printError(cmd, "Error retrieving computation result: %v ❌ ", err)
				return
			}

			cmd.Println(color.New(color.FgGreen).Sprintf("Computation result retrieved and saved successfully! ✔"))
			cmd.Println(color.New(color.FgCyan).Sprintf("📁 Location: %s", absPath))
		},
	}

	cmd.Flags().StringVarP(&outputDir, "output-dir", "o", "", "Directory where the result file will be saved")
	cmd.Flags().StringVarP(&filename, "filename", "f", resultFilename, "Name of the result file (default: results.zip)")

	return cmd
}
