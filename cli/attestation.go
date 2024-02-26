// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/validate"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"google.golang.org/protobuf/encoding/protojson"
)

const reportDataLen = 64

var (
	cfg           check.Config
	cfgString     string
	timeout       time.Duration
	maxRetryDelay time.Duration
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
		Short:   "Retrieve attestation information from agent. Report data expected in hex enoded string of length 64 bytes.",
		Example: "report <report_data>",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			log.Println("Getting attestation")

			reportData, err := hex.DecodeString(args[0])
			if err != nil {
				log.Fatalf("attestation validation and veification failed with error: %s", err)
			}
			if len(reportData) != reportDataLen {
				reportDataSha512 := sha512.Sum512(reportData)
				reportData = reportDataSha512[:]
				log.Printf("length of report data is less than 64, will use sha512 of the data: %s", hex.EncodeToString(reportData))
			}

			result, err := cli.agentSDK.Attestation(cmd.Context(), [64]byte(reportData))
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
	cmd := &cobra.Command{
		Use:     "validate",
		Short:   "Validate and verify attestation information. The report and report data are provided in encoded hex string.",
		Example: "validate <attestation_report> <report_data>",
		Args:    cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			log.Println("Checking attestation")

			report, err := hex.DecodeString(args[0])
			if err != nil {
				log.Fatalf("attestation validation and veification failed with error: %s", err)
			}
			report_data, err := hex.DecodeString(args[1])
			if err != nil {
				log.Fatalf("attestation validation and veification failed with error: %s", err)
			}

			if err := parseConfig(); err != nil {
				log.Fatalf("attestation validation and veification failed with error: %s", err)
			}

			if err := verifyAndValidateAttestation(report, report_data); err != nil {
				log.Fatalf("attestation validation and veification failed with error: %s", err)
			}
			log.Println("Attestation validation and verification is successful!")
		},
	}
	cmd.Flags().StringVar(&cfgString, "config", "", "Serialized json check.Config protobuf. This will overwrite individual flags. Unmarshalled as json. Example: "+`
	{"rootOfTrust":{"product":"test_product","cabundlePaths":["test_cabundlePaths"],"cabundles":["test_Cabundles"],"checkCrl":true,"disallowNetwork":true},"policy":{"minimumGuestSvn":1,"policy":"1","familyId":"AQIDBAUGBwgJCgsMDQ4PEA==","imageId":"AQIDBAUGBwgJCgsMDQ4PEA==","vmpl":0,"minimumTcb":"1","minimumLaunchTcb":"1","platformInfo":"1","requireAuthorKey":true,"reportData":"J+60aXs8btm8VcGgaJYURGeNCu0FIyWMFXQ7ZUlJDC0FJGJizJsOzDIXgQ75UtPC+Zqe0A3dvnnf5VEeQ61RTg==","measurement":"8s78ewoX7Xkfy1qsgVnkZwLDotD768Nqt6qTL5wtQOxHsLczipKM6bhDmWiHLdP4","hostData":"GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw=","reportId":"GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw=","reportIdMa":"GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw=","chipId":"J+60aXs8btm8VcGgaJYURGeNCu0FIyWMFXQ7ZUlJDC0FJGJizJsOzDIXgQ75UtPC+Zqe0A3dvnnf5VEeQ61RTg==","minimumBuild":1,"minimumVersion":"0.90","permitProvisionalFirmware":true,"requireIdBlock":true,"trustedAuthorKeys":["GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="],"trustedAuthorKeyHashes":["GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="],"trustedIdKeys":["GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="],"trustedIdKeyHashes":["GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="],"product":{"name":"SEV_PRODUCT_MILAN","stepping":1,"machineStepping":1}}}`)
	cmd.Flags().BytesHexVar(&cfg.Policy.HostData, "host_data", []byte{}, "The expected HOST_DATA field as a hex string. Must encode 32 bytes. Unchecked if unset.")
	cmd.Flags().StringVar(&cfg.RootOfTrust.Product, "product", "", "The AMD product name for the chip that generated the attestation report.")

	return cmd
}

func verifyAndValidateAttestation(attestation, reportData []byte) error {
	sopts, err := verify.RootOfTrustToOptions(cfg.RootOfTrust)
	if err != nil {
		return err
	}
	sopts.Product = cfg.Policy.Product
	sopts.Getter = &trust.RetryHTTPSGetter{
		Timeout:       timeout,
		MaxRetryDelay: maxRetryDelay,
		Getter:        &trust.SimpleHTTPSGetter{},
	}
	attestationPB, err := abi.ReportCertsToProto(attestation)
	if err != nil {
		return err
	}
	if err = verify.SnpAttestation(attestationPB, sopts); err != nil {
		return err
	}
	opts, err := validate.PolicyToOptions(cfg.Policy)
	if err != nil {
		return err
	}
	opts.ReportData = reportData
	if err = validate.SnpAttestation(attestationPB, opts); err != nil {
		return err
	}
	return nil
}

// parseConfig decodes config passed as json for check.Config struct.
// example
// {"rootOfTrust":{"product":"test_product","cabundlePaths":["test_cabundlePaths"],"cabundles":["test_Cabundles"],"checkCrl":true,"disallowNetwork":true},"policy":{"minimumGuestSvn":1,"policy":"1","familyId":"AQIDBAUGBwgJCgsMDQ4PEA==","imageId":"AQIDBAUGBwgJCgsMDQ4PEA==","vmpl":0,"minimumTcb":"1","minimumLaunchTcb":"1","platformInfo":"1","requireAuthorKey":true,"reportData":"J+60aXs8btm8VcGgaJYURGeNCu0FIyWMFXQ7ZUlJDC0FJGJizJsOzDIXgQ75UtPC+Zqe0A3dvnnf5VEeQ61RTg==","measurement":"8s78ewoX7Xkfy1qsgVnkZwLDotD768Nqt6qTL5wtQOxHsLczipKM6bhDmWiHLdP4","hostData":"GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw=","reportId":"GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw=","reportIdMa":"GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw=","chipId":"J+60aXs8btm8VcGgaJYURGeNCu0FIyWMFXQ7ZUlJDC0FJGJizJsOzDIXgQ75UtPC+Zqe0A3dvnnf5VEeQ61RTg==","minimumBuild":1,"minimumVersion":"0.90","permitProvisionalFirmware":true,"requireIdBlock":true,"trustedAuthorKeys":["GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="],"trustedAuthorKeyHashes":["GSvLKpfu59
// Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="],"trustedIdKeys":["GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="],"trustedIdKeyHashes":["GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="],"product":{"name":"SEV_PRODUCT_MILAN","stepping":1,"machineStepping":1}}}
func parseConfig() error {
	if cfgString == "" {
		return nil
	}
	if err := protojson.Unmarshal([]byte(cfgString), &cfg); err != nil {
		return err
	}
	// Populate fields that should not be nil
	if cfg.RootOfTrust == nil {
		cfg.RootOfTrust = &check.RootOfTrust{}
	}
	if cfg.Policy == nil {
		cfg.Policy = &check.Policy{}
	}
	return nil
}
