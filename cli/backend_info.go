// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/google/go-sev-guest/proto/check"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const (
	filePermision     = 0o755
	hostDataLength    = 32
	measurementLength = 48
)

type AttestationConfiguration struct {
	SNPPolicy   *check.Policy      `json:"snp_policy,omitempty"`
	RootOFTrust *check.RootOfTrust `json:"root_of_trust,omitempty"`
}

func (cli *CLI) NewBackendCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "backend [command]",
		Short: "Change backend information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Change backend information\n\n")
			fmt.Printf("Usage:\n  %s [command]\n\n", cmd.CommandPath())
			fmt.Printf("Available Commands:\n")

			// Filter out "completion" command
			availableCommands := make([]*cobra.Command, 0)
			for _, subCmd := range cmd.Commands() {
				if subCmd.Name() != "completion" {
					availableCommands = append(availableCommands, subCmd)
				}
			}

			for _, subCmd := range availableCommands {
				fmt.Printf("  %-15s%s\n", subCmd.Name(), subCmd.Short)
			}

			fmt.Printf("\nFlags:\n")
			cmd.Flags().VisitAll(func(flag *pflag.Flag) {
				fmt.Printf("  -%s, --%s %s\n", flag.Shorthand, flag.Name, flag.Usage)
			})
			fmt.Printf("\nUse \"%s [command] --help\" for more information about a command.\n", cmd.CommandPath())
		},
	}
}

func (cli *CLI) NewAddMeasurementCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "measurement",
		Short:   "Add measurement to the backend info file. The value should be in base64. The second parameter is backend_info.json file",
		Example: "measurement <measurement> <backend_info.json>",
		Args:    cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			measurement, err := base64.StdEncoding.DecodeString(args[0])
			if err != nil {
				log.Fatalf("Error could not decode base64: %v", err)
			}

			if len(measurement) != measurementLength {
				log.Fatalf("Measurement must be 48 bytes in length")
			}
			attestationConfiguration := AttestationConfiguration{}

			backendInfo, err := os.OpenFile(args[1], os.O_RDWR, filePermision)
			if err != nil {
				log.Fatalf("Error opening the backend information file: %v", err)
			}
			defer backendInfo.Close()

			decoder := json.NewDecoder(backendInfo)
			err = decoder.Decode(&attestationConfiguration)
			if err != nil {
				log.Fatalf("Error decoding the backend information file: %v", err)
			}

			attestationConfiguration.SNPPolicy.Measurement = measurement
			if err = backendInfo.Truncate(0); err != nil {
				log.Fatalf("Error could not truncate backend information JSON file: %v", err)
			}

			fileJson, err := json.MarshalIndent(attestationConfiguration, "", " ")
			if err != nil {
				log.Fatalf("Error marshaling the backend information JSON: %v", err)
			}
			if err = os.WriteFile(backendInfo.Name(), fileJson, filePermision); err != nil {
				log.Fatalf("Error writing into backend information JSON file: %v", err)
			}
		},
	}
}

func (cli *CLI) NewAddHostDataCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "hostdata",
		Short:   "Add host data to the backend info file. The value should be in base64. The second parameter is backend_info.json file",
		Example: "hostdata <host-data> <backend_info.json>",
		Args:    cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			hostData, err := base64.StdEncoding.DecodeString(args[0])
			if err != nil {
				log.Fatalf("Error could not decode base64: %v", err)
			}

			if len(hostData) != hostDataLength {
				log.Fatalf("Host data must be 32 bytes in length")
			}

			attestationConfiguration := AttestationConfiguration{}

			backendInfo, err := os.OpenFile(args[1], os.O_RDWR, filePermision)
			if err != nil {
				log.Fatalf("Error opening the backend information file: %v", err)
			}
			defer backendInfo.Close()

			decoder := json.NewDecoder(backendInfo)
			err = decoder.Decode(&attestationConfiguration)
			if err != nil {
				log.Fatalf("Error decoding the backend information file: %v", err)
			}

			attestationConfiguration.SNPPolicy.HostData = hostData
			if err = backendInfo.Truncate(0); err != nil {
				log.Fatalf("Error could not truncate backend information JSON file: %v", err)
			}

			fileJson, err := json.MarshalIndent(attestationConfiguration, "", " ")
			if err != nil {
				log.Fatalf("Error marshaling the backend information JSON: %v", err)
			}
			if err = os.WriteFile(backendInfo.Name(), fileJson, filePermision); err != nil {
				log.Fatalf("Error writing into backend information JSON file: %v", err)
			}
		},
	}
}
