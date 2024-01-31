// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"fmt"
	"log"
	"os"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/validate"
	"github.com/google/go-sev-guest/verify"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const attestationFilePath = "attestation.txt"

func (cli *CLI) NewAttestationCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "attestation [command]",
		Short: "Get and validate attestations",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Get and validate attestations\n\n")
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

func (cli *CLI) NewGetAttestationCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "get",
		Short:   "Retrieve attestation information from agent",
		Example: "report <report_data>",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			log.Println("Getting attestation")

			result, err := cli.agentSDK.Attestation(cmd.Context(), []byte(args[0]))
			if err != nil {
				log.Fatalf("Error retrieving attestation: %v", err)
			}

			if err = os.WriteFile(attestationFilePath, result, 0o644); err != nil {
				log.Fatalf("Error saving attestation result: %v", err)
			}

			log.Println("Attestation result retrieved and saved successfully!")
		},
	}
}

func (cli *CLI) NewValidateAttestationValidationCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "validate",
		Short:   "Validate and verify attestation information",
		Example: "validate <attestation> <report_data>",
		Args:    cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			log.Println("Checking attestation")

			if err := verifyAndValidateAttestation([]byte(args[0]), []byte(args[1])); err != nil {
				log.Fatalf("attestation validation and veification failed with error: %s", err)
			}
			log.Println("Attestation validation and verification is successful!")
		},
	}
}

func verifyAndValidateAttestation(attestation, reportData []byte) error {
	attestationPB, err := abi.ReportCertsToProto(attestation)
	if err != nil {
		return err
	}
	if err = verify.SnpAttestation(attestationPB, verify.DefaultOptions()); err != nil {
		return err
	}
	if err = validate.SnpAttestation(attestationPB, &validate.Options{ReportData: reportData}); err != nil {
		return err
	}
	return nil
}
