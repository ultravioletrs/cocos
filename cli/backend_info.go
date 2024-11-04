// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"google.golang.org/protobuf/encoding/protojson"
)

type fieldType int

const (
	measurementField fieldType = iota
	hostDataField
)

const (
	// 0o744 file permission gives RWX permission to the user and only the R permission to others.
	filePermission = 0o744
	// Length of the expected host data and measurement field in bytes.
	hostDataLength    = 32
	measurementLength = 48
)

var (
	errDecode                 = errors.New("base64 string could not be decoded")
	errDataLength             = errors.New("data does not have an adequate length")
	errReadingBackendInfoFile = errors.New("error while reading the backend information file")
	errUnmarshalJSON          = errors.New("failed to unmarshal json")
	errMarshalJSON            = errors.New("failed to marshal json")
	errWriteFile              = errors.New("failed to write to file")
	errBackendField           = errors.New("the specified field type does not exist in the backend information")
)

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
			if err := changeAttestationConfiguration(args[1], args[0], measurementLength, measurementField); err != nil {
				printError(cmd, "Error could not change measurement data: %v ❌ ", err)
				return
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
			if err := changeAttestationConfiguration(args[1], args[0], hostDataLength, hostDataField); err != nil {
				printError(cmd, "Error could not change host data: %v ❌ ", err)
				return
			}
		},
	}
}

func changeAttestationConfiguration(fileName, base64Data string, expectedLength int, field fieldType) error {
	data, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return errDecode
	}

	if len(data) != expectedLength {
		return errDataLength
	}

	ac := check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}}

	backendInfo, err := os.ReadFile(fileName)
	if err != nil {
		return errors.Wrap(errReadingBackendInfoFile, err)
	}

	if err = protojson.Unmarshal(backendInfo, &ac); err != nil {
		return errors.Wrap(errUnmarshalJSON, err)
	}

	switch field {
	case measurementField:
		ac.Policy.Measurement = data
	case hostDataField:
		ac.Policy.HostData = data
	default:
		return errBackendField
	}

	fileJson, err := protojson.Marshal(&ac)
	if err != nil {
		return errors.Wrap(errMarshalJSON, err)
	}
	if err = os.WriteFile(fileName, fileJson, filePermission); err != nil {
		return errors.Wrap(errWriteFile, err)
	}
	return nil
}
