// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"encoding/pem"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const (
	imaMeasurementsFilename = "ima_measurements"
)

func (cli *CLI) NewIMAMeasurementsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "ima-measurements",
		Short:   "Retrieve Linux IMA measurements file",
		Example: "ima-measurements <private_key_file_path> <optional_file_name>",
		Args:    cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if cli.connectErr != nil {
				printError(cmd, "Failed to connect to agent: %v ❌ ", cli.connectErr)
				return
			}

			cmd.Println("⏳ Retrieving computation Linux IMA measurements file")

			privKeyFile, err := os.ReadFile(args[0])
			if err != nil {
				printError(cmd, "Error reading private key file: %v ❌ ", err)
				return
			}

			filename := imaMeasurementsFilename
			if len(args) > 1 {
				filename = args[1]
			}

			pemBlock, _ := pem.Decode(privKeyFile)

			privKey, err := decodeKey(pemBlock)
			if err != nil {
				printError(cmd, "Error decoding private key: %v ❌ ", err)
				return
			}

			imaMeasurementsFile, err := os.Create(filename)
			if err != nil {
				printError(cmd, "Error creating imaMeasurements file: %v ❌ ", err)
				return
			}
			defer imaMeasurementsFile.Close()

			pcr10, err := cli.agentSDK.IMAMeasurements(cmd.Context(), privKey, imaMeasurementsFile)
			if err != nil {
				printError(cmd, "Error retrieving Linux IMA measurements file: %v ❌ ", err)
				return
			}

			cmd.Println(color.New(color.FgGreen).Sprintf("Linux IMA measurements file retrieved and saved successfully as %s! PCR10 = %s ✔ ", filename, hex.EncodeToString(pcr10)))

			calculatedPCR10 := make([]byte, 20)

			file, err := os.Open(filename)
			if err != nil {
				printError(cmd, "Failed to open file: %v ❌ ", err)
			}
			defer file.Close()

			scanner := bufio.NewScanner(file)

			for scanner.Scan() {
				line := scanner.Text()
				parts := strings.Fields(line)

				if parts[0] != "10" {
					continue
				}

				digestHex := parts[1]
				if digestHex == strings.Repeat("0", 40) {
					digestHex = strings.Repeat("f", 40)
				}

				digest, err := hex.DecodeString(digestHex)
				if err != nil {
					printError(cmd, "Failed to decode digest: %v ❌ ", err)
					continue
				}

				hasher := sha1.New()
				hasher.Write(calculatedPCR10)
				hasher.Write(digest)
				calculatedPCR10 = hasher.Sum(nil)
			}

			if hex.EncodeToString(pcr10) != hex.EncodeToString(calculatedPCR10) {
				printError(cmd, "Measurements file not verified ❌ ", err)
			} else {
				cmd.Println(color.New(color.FgGreen).Sprintf("Measurements file verified!"))
			}
		},
	}
}
