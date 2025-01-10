// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/fatih/color"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/tools/lib/report"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	defaultMinimumTcb       = 0
	defaultMinimumLaunchTcb = 0
	defaultMinimumGuestSvn  = 0
	defaultGuestPolicy      = 0x0000000000030000
	defaultMinimumBuild     = 0
	defaultCheckCrl         = false
	defaultTimeout          = 2 * time.Minute
	defaultMaxRetryDelay    = 30 * time.Second
	defaultRequireAuthor    = false
	defaultRequireIdBlock   = false
	defaultMinVersion       = "0.0"
	size16                  = 16
	size32                  = 32
	size48                  = 48
	size64                  = 64
	attestationFilePath     = "attestation.bin"
	attestationJson         = "attestation.json"
	sevProductNameMilan     = "Milan"
	sevProductNameGenoa     = "Genoa"
	exampleJSONConfig       = `
	{
		"rootOfTrust":{
		   "product":"test_product",
		   "cabundlePaths":[
			  "test_cabundlePaths"
		   ],
		   "cabundles":[
			  "test_Cabundles"
		   ],
		   "checkCrl":true,
		   "disallowNetwork":true
		},
		"policy":{
		   "minimumGuestSvn":1,
		   "policy":"1",
		   "familyId":"AQIDBAUGBwgJCgsMDQ4PEA==",
		   "imageId":"AQIDBAUGBwgJCgsMDQ4PEA==",
		   "vmpl":0,
		   "minimumTcb":"1",
		   "minimumLaunchTcb":"1",
		   "platformInfo":"1",
		   "requireAuthorKey":true,
		   "reportData":"J+60aXs8btm8VcGgaJYURGeNCu0FIyWMFXQ7ZUlJDC0FJGJizJsOzDIXgQ75UtPC+Zqe0A3dvnnf5VEeQ61RTg==",
		   "measurement":"8s78ewoX7Xkfy1qsgVnkZwLDotD768Nqt6qTL5wtQOxHsLczipKM6bhDmWiHLdP4",
		   "hostData":"GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw=",
		   "reportId":"GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw=",
		   "reportIdMa":"GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw=",
		   "chipId":"J+60aXs8btm8VcGgaJYURGeNCu0FIyWMFXQ7ZUlJDC0FJGJizJsOzDIXgQ75UtPC+Zqe0A3dvnnf5VEeQ61RTg==",
		   "minimumBuild":1,
		   "minimumVersion":"0.90",
		   "permitProvisionalFirmware":true,
		   "requireIdBlock":true,
		   "trustedAuthorKeys":[
			  "GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="
		   ],
		   "trustedAuthorKeyHashes":[
			  "GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="
		   ],
		   "trustedIdKeys":[
			  "GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="
		   ],
		   "trustedIdKeyHashes":[
			  "GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="
		   ],
		   "product":{
			  "name":"SEV_PRODUCT_MILAN",
			  "stepping":1,
			  "machineStepping":1
		   }
		}
	}
	`
)

var (
	cfg                 = check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}}
	cfgString           string
	timeout             time.Duration
	maxRetryDelay       time.Duration
	platformInfo        string
	stepping            string
	trustedAuthorKeys   []string
	trustedAuthorHashes []string
	trustedIdKeys       []string
	trustedIdKeyHashes  []string
	attestationFile     string
	attestation         []byte
	empty16             = [size16]byte{}
	empty32             = [size32]byte{}
	empty64             = [size64]byte{}
	defaultReportIdMa   = []byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}
	getJsonAttestation  bool
	errReportSize       = errors.New("attestation contents too small")
)

func (cli *CLI) NewAttestationCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "attestation [command]",
		Short: "Get and validate attestations",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Printf("Get and validate attestations\n\n")
			cmd.Printf("Usage:\n  %s [command]\n\n", cmd.CommandPath())
			cmd.Printf("Available Commands:\n")

			// Filter out "completion" command
			availableCommands := make([]*cobra.Command, 0)
			for _, subCmd := range cmd.Commands() {
				if subCmd.Name() != "completion" {
					availableCommands = append(availableCommands, subCmd)
				}
			}

			for _, subCmd := range availableCommands {
				cmd.Printf("  %-15s%s\n", subCmd.Name(), subCmd.Short)
			}

			cmd.Printf("\nFlags:\n")
			cmd.Flags().VisitAll(func(flag *pflag.Flag) {
				cmd.Printf("  -%s, --%s %s\n", flag.Shorthand, flag.Name, flag.Usage)
			})
			cmd.Printf("\nUse \"%s [command] --help\" for more information about a command.\n", cmd.CommandPath())
		},
	}
}

func (cli *CLI) NewGetAttestationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "get",
		Short:   "Retrieve attestation information from agent. Report data expected in hex enoded string of length 64 bytes.",
		Example: "get <report_data>",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if cli.connectErr != nil {
				printError(cmd, "Failed to connect to agent: %v ❌ ", cli.connectErr)
				return
			}

			cmd.Println("Getting attestation")

			reportData, err := hex.DecodeString(args[0])
			if err != nil {
				printError(cmd, "Error decoding report data: %v ❌ ", err)
				return
			}
			if len(reportData) != agent.ReportDataSize {
				msg := color.New(color.FgRed).Sprintf("report data must be a hex encoded string of length %d bytes ❌ ", agent.ReportDataSize)
				cmd.Println(msg)
				return
			}

			filename := attestationFilePath
			if getJsonAttestation {
				filename = attestationJson
			}

			attestationFile, err := os.Create(filename)
			if err != nil {
				printError(cmd, "Error creating attestation file: %v ❌ ", err)
				return
			}

			if err := cli.agentSDK.Attestation(cmd.Context(), [agent.ReportDataSize]byte(reportData), attestationFile); err != nil {
				printError(cmd, "Failed to get attestation due to error: %v ❌ ", err)
				return
			}

			if err := attestationFile.Close(); err != nil {
				printError(cmd, "Error closing attestation file: %v ❌ ", err)
				return
			}

			if getJsonAttestation {
				result, err := os.ReadFile(filename)
				if err != nil {
					printError(cmd, "Error reading attestation file: %v ❌ ", err)
					return
				}

				result, err = attesationToJSON(result)
				if err != nil {
					printError(cmd, "Error converting attestation to json: %v ❌ ", err)
					return
				}

				if err := os.WriteFile(filename, result, 0o644); err != nil {
					printError(cmd, "Error writing attestation file: %v ❌ ", err)
					return
				}
			}

			cmd.Println("Attestation result retrieved and saved successfully!")
		},
	}

	cmd.Flags().BoolVarP(&getJsonAttestation, "json", "j", false, "Get attestation in json format")

	return cmd
}

func attesationToJSON(report []byte) ([]byte, error) {
	if len(report) < abi.ReportSize {
		return nil, errors.Wrap(errReportSize, fmt.Errorf("attestation contents too small (0x%x bytes). Want at least 0x%x bytes", len(report), abi.ReportSize))
	}
	attestationPB, err := abi.ReportCertsToProto(report[:abi.ReportSize])
	if err != nil {
		return nil, err
	}

	return json.MarshalIndent(attestationPB, "", "	")
}

func attesationFromJSON(reportFile []byte) ([]byte, error) {
	var attestationPB sevsnp.Attestation
	if err := json.Unmarshal(reportFile, &attestationPB); err != nil {
		return nil, err
	}

	return report.Transform(&attestationPB, "bin")
}

func isFileJSON(filename string) bool {
	return strings.HasSuffix(filename, ".json")
}

func (cli *CLI) NewValidateAttestationValidationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "validate",
		Short:   "Validate and verify attestation information. The report is provided as a file path.",
		Example: "validate <attestation_report_file_path>",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println("Checking attestation")

			attestationFile = string(args[0])

			if err := parseConfig(); err != nil {
				printError(cmd, "Error parsing config: %v ❌ ", err)
				return
			}
			if err := parseHashes(); err != nil {
				printError(cmd, "Error parsing hashes: %v ❌ ", err)
				return
			}
			if err := parseFiles(); err != nil {
				printError(cmd, "Error parsing files: %v ❌ ", err)
				return
			}
			// This format is the attestation report in AMD's specified ABI format, immediately
			// followed by the certificate table bytes.
			if len(attestation) < abi.ReportSize {
				msg := color.New(color.FgRed).Sprintf("attestation contents too small (0x%x bytes). Want at least 0x%x bytes ❌ ", len(attestation), abi.ReportSize)
				cmd.Println(msg)
				return
			}
			if err := parseUints(); err != nil {
				printError(cmd, "Error parsing uints: %v ❌ ", err)
				return
			}
			cfg.Policy.Vmpl = wrapperspb.UInt32(0)

			if err := validateInput(); err != nil {
				printError(cmd, "Error validating input: %v ❌ ", err)
				return
			}

			if err := quoteprovider.VerifyAndValidate(attestation, &cfg); err != nil {
				printError(cmd, "Attestation validation and verification failed with error: %v ❌ ", err)
				return
			}
			cmd.Println("Attestation validation and verification is successful!")
		},
	}
	cmd.Flags().StringVar(
		&cfgString,
		"config",
		"",
		"Serialized json check.Config protobuf. This will overwrite individual flags. Unmarshalled as json. Example: "+exampleJSONConfig,
	)
	cmd.Flags().BytesHexVar(
		&cfg.Policy.HostData,
		"host_data",
		empty32[:],
		"The expected HOST_DATA field as a hex string. Must encode 32 bytes. Unchecked if unset.",
	)
	cmd.Flags().BytesHexVar(
		&cfg.Policy.ReportData,
		"report_data",
		empty64[:],
		"The expected REPORT_DATA field as a hex string. Must encode 64 bytes. Must be set.",
	)
	cmd.Flags().BytesHexVar(
		&cfg.Policy.FamilyId,
		"family_id",
		empty16[:],
		"The expected FAMILY_ID field as a hex string. Must encode 16 bytes. Unchecked if unset.",
	)
	cmd.Flags().BytesHexVar(
		&cfg.Policy.ImageId,
		"image_id",
		empty16[:],
		"The expected IMAGE_ID field as a hex string. Must encode 16 bytes. Unchecked if unset.",
	)
	cmd.Flags().BytesHexVar(
		&cfg.Policy.ReportId,
		"report_id",
		nil,
		"The expected REPORT_ID field as a hex string. Must encode 32 bytes. Unchecked if unset.",
	)
	cmd.Flags().BytesHexVar(
		&cfg.Policy.ReportIdMa,
		"report_id_ma",
		defaultReportIdMa,
		"The expected REPORT_ID_MA field as a hex string. Must encode 32 bytes. Unchecked if unset.",
	)
	cmd.Flags().BytesHexVar(
		&cfg.Policy.Measurement,
		"measurement",
		nil,
		"The expected MEASUREMENT field as a hex string. Must encode 48 bytes. Unchecked if unset.",
	)
	cmd.Flags().BytesHexVar(
		&cfg.Policy.ChipId,
		"chip_id",
		nil,
		"The expected MEASUREMENT field as a hex string. Must encode 48 bytes. Unchecked if unset.",
	)
	cmd.Flags().Uint64Var(
		&cfg.Policy.MinimumTcb,
		"minimum_tcb",
		defaultMinimumTcb,
		"The minimum acceptable value for CURRENT_TCB, COMMITTED_TCB, and REPORTED_TCB.",
	)
	cmd.Flags().Uint64Var(
		&cfg.Policy.MinimumLaunchTcb,
		"minimum_lauch_tcb",
		defaultMinimumLaunchTcb,
		"The minimum acceptable value for LAUNCH_TCB.",
	)
	cmd.Flags().Uint64Var(
		&cfg.Policy.Policy,
		"guest_policy",
		defaultGuestPolicy,
		"The most acceptable guest SnpPolicy.",
	)
	cmd.Flags().Uint32Var(
		&cfg.Policy.MinimumGuestSvn,
		"minimum_guest_svn",
		defaultMinimumGuestSvn,
		"The most acceptable GUEST_SVN.",
	)
	cmd.Flags().Uint32Var(
		&cfg.Policy.MinimumBuild,
		"minimum_build",
		defaultMinimumBuild,
		"The 8-bit minimum build number for AMD-SP firmware",
	)
	cmd.Flags().BoolVar(
		&cfg.RootOfTrust.CheckCrl,
		"check_crl",
		defaultCheckCrl,
		"Download and check the CRL for revoked certificates.",
	)
	cmd.Flags().DurationVar(
		&timeout,
		"timeout",
		defaultTimeout,
		"Duration to continue to retry failed HTTP requests.",
	)
	cmd.Flags().DurationVar(
		&maxRetryDelay,
		"max_retry_delay",
		defaultMaxRetryDelay,
		"Maximum Duration to wait between HTTP request retries.",
	)
	cmd.Flags().BoolVar(
		&cfg.Policy.RequireAuthorKey,
		"require_author_key",
		defaultRequireAuthor,
		"Require that AUTHOR_KEY_EN is 1.",
	)
	cmd.Flags().BoolVar(
		&cfg.Policy.RequireIdBlock,
		"require_id_block",
		defaultRequireIdBlock,
		"Require that the VM was launch with an ID_BLOCK signed by a trusted id key or author key",
	)
	cmd.Flags().StringVar(
		&platformInfo,
		"platform_info",
		"",
		"The maximum acceptable PLATFORM_INFO field bit-wise. May be empty or a 64-bit unsigned integer",
	)
	cmd.Flags().StringVar(
		&cfg.Policy.MinimumVersion,
		"minimum_version",
		defaultMinVersion,
		"Minimum AMD-SP firmware API version (major.minor). Each number must be 8-bit non-negative.",
	)
	cmd.Flags().StringArrayVar(
		&trustedAuthorKeys,
		"trusted_author_keys",
		[]string{},
		"Paths to x.509 certificates of trusted author keys",
	)
	cmd.Flags().StringArrayVar(
		&trustedAuthorHashes,
		"trusted_author_key_hashes",
		[]string{},
		"Hex-encoded SHA-384 hash values of trusted author keys in AMD public key format",
	)
	cmd.Flags().StringArrayVar(
		&trustedIdKeys,
		"trusted_id_keys",
		[]string{},
		"Paths to x.509 certificates of trusted author keys",
	)
	cmd.Flags().StringArrayVar(
		&trustedIdKeyHashes,
		"trusted_id_key_hashes",
		[]string{},
		"Hex-encoded SHA-384 hash values of trusted identity keys in AMD public key format",
	)
	cmd.Flags().StringVar(
		&cfg.RootOfTrust.ProductLine,
		"product",
		"",
		"The AMD product name for the chip that generated the attestation report.",
	)
	cmd.Flags().StringVar(
		&stepping,
		"stepping",
		"",
		"The machine stepping for the chip that generated the attestation report. Default unchecked.",
	)
	cmd.Flags().StringArrayVar(
		&cfg.RootOfTrust.CabundlePaths,
		"CA_bundles_paths",
		[]string{},
		"Paths to CA bundles for the AMD product. Must be in PEM format, ASK, then ARK certificates. If unset, uses embedded root certificates.",
	)
	cmd.Flags().StringArrayVar(
		&cfg.RootOfTrust.Cabundles,
		"CA_bundles",
		[]string{},
		"PEM format CA bundles for the AMD product. Combined with contents of cabundle_paths.",
	)

	if err := cmd.MarkFlagRequired("report_data"); err != nil {
		printError(cmd, "Failed to mark flag as required: %v ❌ ", err)
		return nil
	}

	if err := cmd.MarkFlagRequired("product"); err != nil {
		printError(cmd, "Failed to mark flag as required: %v ❌ ", err)
		return nil
	}

	return cmd
}

// parseConfig decodes config passed as json for check.Config struct.
// example
/* {
	"rootOfTrust":{
		"product":"test_product",
		"cabundlePaths":[
		   "test_cabundlePaths"
		],
		"cabundles":[
		   "test_Cabundles"
		],
		"checkCrl":true,
		"disallowNetwork":true
	 },
	 "policy":{
		"minimumGuestSvn":1,
		"policy":"1",
		"familyId":"AQIDBAUGBwgJCgsMDQ4PEA==",
		"imageId":"AQIDBAUGBwgJCgsMDQ4PEA==",
		"vmpl":0,
		"minimumTcb":"1",
		"minimumLaunchTcb":"1",
		"platformInfo":"1",
		"requireAuthorKey":true,
		"reportData":"J+60aXs8btm8VcGgaJYURGeNCu0FIyWMFXQ7ZUlJDC0FJGJizJsOzDIXgQ75UtPC+Zqe0A3dvnnf5VEeQ61RTg==",
		"measurement":"8s78ewoX7Xkfy1qsgVnkZwLDotD768Nqt6qTL5wtQOxHsLczipKM6bhDmWiHLdP4",
		"hostData":"GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw=",
		"reportId":"GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw=",
		"reportIdMa":"GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw=",
		"chipId":"J+60aXs8btm8VcGgaJYURGeNCu0FIyWMFXQ7ZUlJDC0FJGJizJsOzDIXgQ75UtPC+Zqe0A3dvnnf5VEeQ61RTg==",
		"minimumBuild":1,
		"minimumVersion":"0.90",
		"permitProvisionalFirmware":true,
		"requireIdBlock":true,
		"trustedAuthorKeys":[
		   "GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="
		],
		"trustedAuthorKeyHashes":[
		   "GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="
		],
		"trustedIdKeys":[
		   "GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="
		],
		"trustedIdKeyHashes":[
		   "GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="
		],
		"product":{
		   "name":"SEV_PRODUCT_MILAN",
		   "stepping":1,
		   "machineStepping":1
		}
	 }
  }*/
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

func parseHashes() error {
	for _, hash := range trustedAuthorHashes {
		hashBytes, err := hex.DecodeString(hash)
		if err != nil {
			return err
		}
		cfg.Policy.TrustedAuthorKeyHashes = append(cfg.Policy.TrustedAuthorKeyHashes, hashBytes)
	}
	for _, hash := range trustedIdKeyHashes {
		hashBytes, err := hex.DecodeString(hash)
		if err != nil {
			return err
		}
		cfg.Policy.TrustedIdKeyHashes = append(cfg.Policy.TrustedIdKeyHashes, hashBytes)
	}
	return nil
}

func parseFiles() error {
	file, err := os.ReadFile(attestationFile)
	if err != nil {
		return err
	}
	attestation = file
	if isFileJSON(attestationFile) {
		attestation, err = attesationFromJSON(attestation)
		if err != nil {
			return err
		}
	}

	for _, path := range trustedAuthorKeys {
		file, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		cfg.Policy.TrustedAuthorKeys = append(cfg.Policy.TrustedAuthorKeys, file)
	}
	for _, path := range trustedIdKeys {
		file, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		cfg.Policy.TrustedIdKeys = append(cfg.Policy.TrustedIdKeys, file)
	}
	return nil
}

func parseUints() error {
	if stepping != "" {
		if base := getBase(stepping); base == 10 {
			num, err := strconv.ParseUint(stepping, getBase(stepping), 8)
			if err != nil {
				return err
			}
			cfg.Policy.Product.MachineStepping = wrapperspb.UInt32(uint32(num))
		} else {
			num, err := strconv.ParseUint(stepping[2:], base, 8)
			if err != nil {
				return err
			}
			cfg.Policy.Product.MachineStepping = wrapperspb.UInt32(uint32(num))
		}
	}
	if platformInfo != "" {
		if base := getBase(platformInfo); base == 10 {
			num, err := strconv.ParseUint(platformInfo, getBase(platformInfo), 8)
			if err != nil {
				return err
			}
			cfg.Policy.PlatformInfo = wrapperspb.UInt64(num)
		} else {
			num, err := strconv.ParseUint(platformInfo[2:], base, 8)
			if err != nil {
				return err
			}
			cfg.Policy.PlatformInfo = wrapperspb.UInt64(num)
		}
	}
	return nil
}

func getBase(val string) int {
	switch {
	case strings.HasPrefix(val, "0x"):
		return 16
	case strings.HasPrefix(val, "0o"):
		return 8
	case strings.HasPrefix(val, "0b"):
		return 2
	default:
		return 10
	}
}

func validateInput() error {
	if len(cfg.RootOfTrust.CabundlePaths) != 0 || len(cfg.RootOfTrust.Cabundles) != 0 && cfg.RootOfTrust.ProductLine == "" {
		return fmt.Errorf("product name must be set if CA bundles are provided")
	}

	if err := validateFieldLength("report_data", cfg.Policy.ReportData, size64); err != nil {
		return err
	}
	if err := validateFieldLength("host_data", cfg.Policy.HostData, size32); err != nil {
		return err
	}
	if err := validateFieldLength("family_id", cfg.Policy.FamilyId, size16); err != nil {
		return err
	}
	if err := validateFieldLength("image_id", cfg.Policy.ImageId, size16); err != nil {
		return err
	}
	if err := validateFieldLength("report_id", cfg.Policy.ReportId, size32); err != nil {
		return err
	}
	if err := validateFieldLength("report_id_ma", cfg.Policy.ReportIdMa, size32); err != nil {
		return err
	}
	if err := validateFieldLength("measurement", cfg.Policy.Measurement, size48); err != nil {
		return err
	}
	if err := validateFieldLength("chip_id", cfg.Policy.ChipId, size64); err != nil {
		return err
	}
	for _, hash := range cfg.Policy.TrustedAuthorKeyHashes {
		if err := validateFieldLength("trusted_author_key_hash", hash, size48); err != nil {
			return err
		}
	}
	for _, hash := range cfg.Policy.TrustedIdKeyHashes {
		if err := validateFieldLength("trusted_id_key_hash", hash, size48); err != nil {
			return err
		}
	}
	return nil
}

func validateFieldLength(fieldName string, field []byte, expectedLength int) error {
	if field != nil && len(field) != expectedLength {
		return fmt.Errorf("%s length should be at least %d bytes long", fieldName, expectedLength)
	}
	return nil
}
