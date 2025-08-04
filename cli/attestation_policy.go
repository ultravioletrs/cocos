// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/azure"
	"github.com/ultravioletrs/cocos/pkg/attestation/gcp"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"google.golang.org/protobuf/proto"
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
	errDecode                              = errors.New("base64 string could not be decoded")
	errDataLength                          = errors.New("data does not have an adequate length")
	errReadingAttestationPolicyFile        = errors.New("error while reading the attestation policy file")
	errUnmarshalJSON                       = errors.New("failed to unmarshal json")
	errMarshalJSON                         = errors.New("failed to marshal json")
	errWriteFile                           = errors.New("failed to write to file")
	errAttestationPolicyField              = errors.New("the specified field type does not exist in the attestation policy")
	errReadingManifestFile                 = errors.New("error while reading manifest file")
	errDecodeHex                           = errors.New("error decoding hex string")
	policy                          uint64 = 196639
)

func (cli *CLI) NewAttestationPolicyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "policy [command]",
		Short: "Change attestation policy",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Change attestation policy\n\n")
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
		Short:   "Add measurement to the attestation policy file. The value should be in base64. The second parameter is attestation_policy.json file",
		Example: "measurement <measurement> <attestation_policy.json>",
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
		Short:   "Add host data to the attestation policy file. The value should be in base64. The second parameter is attestation_policy.json file",
		Example: "hostdata <host-data> <attestation_policy.json>",
		Args:    cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			if err := changeAttestationConfiguration(args[1], args[0], hostDataLength, hostDataField); err != nil {
				printError(cmd, "Error could not change host data: %v ❌ ", err)
				return
			}
		},
	}
}

func (cli *CLI) NewGCPAttestationPolicy() *cobra.Command {
	return &cobra.Command{
		Use:     "gcp",
		Short:   "Get attestation policy for GCP CVM",
		Example: `gcp <bin_vtmp_attestation_report_file> <vcpu_count>`,
		Args:    cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			attestationBin, err := os.ReadFile(args[0])
			if err != nil {
				printError(cmd, "Error reading attestation report file: %v ❌ ", err)
				return
			}

			vcpuCount, err := strconv.Atoi(args[1])
			if err != nil {
				printError(cmd, "Error converting vCPU count to integer: %v ❌ ", err)
				return
			}

			attestation := &attest.Attestation{}

			if err := proto.Unmarshal(attestationBin, attestation); err != nil {
				printError(cmd, "Error unmarshaling attestation report: %v ❌ ", err)
				return
			}

			attestationPB := attestation.GetSevSnpAttestation()

			measurement, err := gcp.Extract384BitMeasurement(attestationPB)
			if err != nil {
				printError(cmd, "Error extracting 384-bit measurement: %v ❌ ", err)
				return
			}

			launchEndorsement, err := gcp.GetLaunchEndorsement(cmd.Context(), measurement)
			if err != nil {
				printError(cmd, "Error getting launch endorsement: %v ❌ ", err)
				return
			}

			attestationPolicy, err := gcp.GenerateAttestationPolicy(launchEndorsement, uint32(vcpuCount))
			if err != nil {
				printError(cmd, "Error generating attestation policy: %v ❌ ", err)
				return
			}

			attestationPolicyJson, err := json.MarshalIndent(attestationPolicy, "", "  ")
			if err != nil {
				printError(cmd, "Error marshaling attestation policy: %v ❌ ", err)
				return
			}

			if err := os.WriteFile("attestation_policy.json", attestationPolicyJson, filePermission); err != nil {
				printError(cmd, "Error writing attestation policy file: %v ❌ ", err)
				return
			}

			cmd.Println("Attestation policy file generated successfully ✅")
		},
	}
}

func (cli *CLI) NewDownloadGCPOvmfFile() *cobra.Command {
	return &cobra.Command{
		Use:     "download",
		Short:   "Download GCP OVMF file",
		Example: `download <bin_vtmp_attestation_report_file>`,
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			attestationBin, err := os.ReadFile(args[0])
			if err != nil {
				printError(cmd, "Error reading attestation report file: %v ❌ ", err)
				return
			}

			attestation := &attest.Attestation{}

			if err := proto.Unmarshal(attestationBin, attestation); err != nil {
				printError(cmd, "Error unmarshaling attestation report: %v ❌ ", err)
				return
			}

			attestationPB := attestation.GetSevSnpAttestation()

			measurement, err := gcp.Extract384BitMeasurement(attestationPB)
			if err != nil {
				printError(cmd, "Error extracting 384-bit measurement: %v ❌ ", err)
				return
			}

			launchEndorsement, err := gcp.GetLaunchEndorsement(cmd.Context(), measurement)
			if err != nil {
				printError(cmd, "Error getting launch endorsement: %v ❌ ", err)
				return
			}

			ovmf, err := gcp.DownloadOvmfFile(cmd.Context(), fmt.Sprintf("%x", launchEndorsement.Digest))
			if err != nil {
				printError(cmd, "Error downloading OVMF file: %v ❌ ", err)
				return
			}

			sum384 := sha512.Sum384(ovmf)

			if !bytes.Equal(sum384[:], launchEndorsement.Digest) {
				printError(cmd, "Error OVMF file does not match the measurement: %v ❌ ", fmt.Errorf("digest mismatch"))
			} else {
				cmd.Println("OVMF firmware in vm is unmodified ✅")
			}

			if err := os.WriteFile("ovmf.fd", ovmf, filePermission); err != nil {
				printError(cmd, "Error writing OVMF file: %v ❌ ", err)
				return
			}

			cmd.Println("OVMF file downloaded successfully ✅")
		},
	}
}

func (cli *CLI) NewAzureAttestationPolicy() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "azure",
		Short:   "Get attestation policy for Azure CVM",
		Example: `azure <azure_maa_token_file> <product_name>`,
		Args:    cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			token, err := os.ReadFile(args[0])
			if err != nil {
				printError(cmd, "Error reading attestation report file: %v ❌ ", err)
				return
			}

			product := args[1]

			config, err := azure.GenerateAttestationPolicy(string(token), product, policy)
			if err != nil {
				printError(cmd, "Error generating attestation policy: %v ❌ ", err)
				return
			}

			attestationPolicyJson, err := json.MarshalIndent(&config, "", " ")
			if err != nil {
				printError(cmd, "Error marshaling attestation policy: %v ❌ ", err)
				return
			}

			if err := os.WriteFile("attestation_policy.json", attestationPolicyJson, filePermission); err != nil {
				printError(cmd, "Error writing attestation policy file: %v ❌ ", err)
				return
			}

			cmd.Println("Attestation policy file generated successfully ✅")
		},
	}

	cmd.Flags().Uint64Var(
		&policy,
		"policy",
		policy,
		"Policy of the guest CVM",
	)

	return cmd
}

func (cli *CLI) NewExtendWithManifestCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "extend",
		Short:   "Extends PCR16 with computation manifests. The first parameter is path to attestation policy file. The rest of the parameters are paths to computation manifest files.",
		Example: "extend <attestation_policy_file_path> <computation_manifest_file_path> [<computation_manifest_file_path> ...]",
		Args:    cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			attestationPolicyFilePath := args[0]
			manifestPaths := args[1:]
			if err := extendWithManifest(attestationPolicyFilePath, manifestPaths); err != nil {
				printError(cmd, "Error could not change measurement data: %v ❌ ", err)
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

	ac := attestation.Config{Config: &check.Config{RootOfTrust: &check.RootOfTrust{}, Policy: &check.Policy{}}, PcrConfig: &attestation.PcrConfig{}}

	f, err := os.ReadFile(fileName)
	if err != nil {
		return errors.Wrap(errReadingAttestationPolicyFile, err)
	}

	if err = vtpm.ReadPolicyFromByte(f, &ac); err != nil {
		return errors.Wrap(errUnmarshalJSON, err)
	}

	if ac.Config.Policy == nil {
		ac.Config.Policy = &check.Policy{}
	}

	switch field {
	case measurementField:
		ac.Config.Policy.Measurement = data
	case hostDataField:
		ac.Config.Policy.HostData = data
	default:
		return errAttestationPolicyField
	}

	fileJson, err := vtpm.ConvertPolicyToJSON(&ac)
	if err != nil {
		return errors.Wrap(errMarshalJSON, err)
	}
	if err = os.WriteFile(fileName, fileJson, filePermission); err != nil {
		return errors.Wrap(errWriteFile, err)
	}
	return nil
}

func extendWithManifest(attestationPolicyPath string, manifestPath []string) error {
	attestationConfig := attestation.Config{Config: &check.Config{RootOfTrust: &check.RootOfTrust{}, Policy: &check.Policy{}}, PcrConfig: &attestation.PcrConfig{}}

	attestationPolicyFileData, err := os.ReadFile(attestationPolicyPath)
	if err != nil {
		return errors.Wrap(errReadingAttestationPolicyFile, err)
	}

	if err = vtpm.ReadPolicyFromByte(attestationPolicyFileData, &attestationConfig); err != nil {
		return errors.Wrap(errUnmarshalJSON, err)
	}

	for _, manifestPath := range manifestPath {
		manifest, err := os.ReadFile(manifestPath)
		if err != nil {
			return errors.Wrap(errReadingManifestFile, err)
		}

		manifestSha256 := sha512.Sum512_256(manifest)
		manifestSha384 := sha512.Sum384(manifest)

		data256, exists256 := attestationConfig.PCRValues.Sha256["16"]

		if !exists256 {
			data256 = "0000000000000000000000000000000000000000000000000000000000000000"
		}

		byteData256, err := hex.DecodeString(data256)
		if err != nil {
			return errors.Wrap(errDecodeHex, err)
		}

		newByteData256 := sha512.Sum512_256(append(byteData256, manifestSha256[:]...))

		data384, exists384 := attestationConfig.PCRValues.Sha384["16"]

		if !exists384 {
			data384 = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
		}

		byteData384, err := hex.DecodeString(data384)
		if err != nil {
			return errors.Wrap(errDecodeHex, err)
		}

		newByteData384 := sha512.Sum384(append(byteData384, manifestSha384[:]...))

		attestationConfig.PCRValues.Sha256["16"] = hex.EncodeToString(newByteData256[:])
		attestationConfig.PCRValues.Sha384["16"] = hex.EncodeToString(newByteData384[:])
	}

	attestationPolicyJSON, err := vtpm.ConvertPolicyToJSON(&attestationConfig)
	if err != nil {
		return errors.Wrap(errMarshalJSON, err)
	}
	if err = os.WriteFile(attestationPolicyPath, attestationPolicyJSON, filePermission); err != nil {
		return errors.Wrap(errWriteFile, err)
	}

	return nil
}
