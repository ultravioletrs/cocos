// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/validate"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	defaultMinimumTcb                = 0
	defaultMinimumLaunchTcb          = 0
	defaultMinimumGuestSvn           = (1 << 17)
	defaultMinimumBuild              = 0
	defaultCheckCrl                  = false
	defaultDisallowNetwork           = false
	defaultTimeout                   = 2 * time.Minute
	defaultMaxRetryDelay             = 30 * time.Second
	defaultRequireAuthor             = false
	defaultRequireIdBlock            = false
	defaultPermitProvisionalSoftware = false
	size16                           = 16
	size32                           = 32
	size48                           = 48
	size64                           = 64
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
				log.Fatalf("attestation validation and verification failed with error: %s", err)
			}
			if len(reportData) != sha512.Size {
				log.Fatalf("report data must be a hex encoded string of length %d bytes", sha512.Size)
			}

			result, err := cli.agentSDK.Attestation(cmd.Context(), [sha512.Size]byte(reportData))
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
		Short:   "Validate and verify attestation information. The report is provided as a file path.",
		Example: "validate <attestation_report_file_path>",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			log.Println("Checking attestation")

			attestationFile = string(args[0])

			if err := parseConfig(); err != nil {
				log.Fatalf("attestation validation and verification failed with error: %s", err)
			}
			if err := parseHashes(); err != nil {
				log.Fatalf("attestation validation and verification failed with error: %s", err)
			}
			if err := parseFiles(); err != nil {
				log.Fatalf("attestation validation and verification failed with error: %s", err)
			}
			// This format is the attestation report in AMD's specified ABI format, immediately
			// followed by the certificate table bytes.
			if len(attestation) < abi.ReportSize {
				log.Fatalf("attestation contents too small (0x%x bytes). Want at least 0x%x bytes", len(attestation), abi.ReportSize)
			}
			if err := parseUints(); err != nil {
				log.Fatalf("attestation validation and verification failed with error: %s", err)
			}
			cfg.Policy.Vmpl = wrapperspb.UInt32(0)

			if err := validateInput(); err != nil {
				log.Fatalf("attestation validation and verification failed with error: %s", err)
			}

			if err := verifyAndValidateAttestation(attestation); err != nil {
				log.Fatalf("attestation validation and verification failed with error: %s", err)
			}
			log.Println("Attestation validation and verification is successful!")
		},
	}
	cmd.Flags().StringVar(&cfgString, "config", "", "Serialized json check.Config protobuf. This will overwrite individual flags. Unmarshalled as json. Example: "+`
	{"rootOfTrust":{"product":"test_product","cabundlePaths":["test_cabundlePaths"],"cabundles":["test_Cabundles"],"checkCrl":true,"disallowNetwork":true},"policy":{"minimumGuestSvn":1,"policy":"1","familyId":"AQIDBAUGBwgJCgsMDQ4PEA==","imageId":"AQIDBAUGBwgJCgsMDQ4PEA==","vmpl":0,"minimumTcb":"1","minimumLaunchTcb":"1","platformInfo":"1","requireAuthorKey":true,"reportData":"J+60aXs8btm8VcGgaJYURGeNCu0FIyWMFXQ7ZUlJDC0FJGJizJsOzDIXgQ75UtPC+Zqe0A3dvnnf5VEeQ61RTg==","measurement":"8s78ewoX7Xkfy1qsgVnkZwLDotD768Nqt6qTL5wtQOxHsLczipKM6bhDmWiHLdP4","hostData":"GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw=","reportId":"GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw=","reportIdMa":"GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw=","chipId":"J+60aXs8btm8VcGgaJYURGeNCu0FIyWMFXQ7ZUlJDC0FJGJizJsOzDIXgQ75UtPC+Zqe0A3dvnnf5VEeQ61RTg==","minimumBuild":1,"minimumVersion":"0.90","permitProvisionalFirmware":true,"requireIdBlock":true,"trustedAuthorKeys":["GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="],"trustedAuthorKeyHashes":["GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="],"trustedIdKeys":["GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="],"trustedIdKeyHashes":["GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="],"product":{"name":"SEV_PRODUCT_MILAN","stepping":1,"machineStepping":1}}}`)
	cmd.Flags().BytesHexVar(&cfg.Policy.HostData, "host_data", []byte{}, "The expected HOST_DATA field as a hex string. Must encode 32 bytes. Unchecked if unset.")
	cmd.Flags().BytesHexVar(&cfg.Policy.ReportData, "report_data", []byte{}, "The expected REPORT_DATA field as a hex string. Must encode 64 bytes. Must be set.")
	cmd.Flags().BytesHexVar(&cfg.Policy.FamilyId, "family_id", []byte{}, "The expected FAMILY_ID field as a hex string. Must encode 16 bytes. Unchecked if unset.")
	cmd.Flags().BytesHexVar(&cfg.Policy.ImageId, "image_id", []byte{}, "The expected IMAGE_ID field as a hex string. Must encode 16 bytes. Unchecked if unset.")
	cmd.Flags().BytesHexVar(&cfg.Policy.ReportId, "report_id", []byte{}, "The expected REPORT_ID field as a hex string. Must encode 32 bytes. Unchecked if unset.")
	cmd.Flags().BytesHexVar(&cfg.Policy.ReportIdMa, "report_id_ma", []byte{}, "The expected REPORT_ID_MA field as a hex string. Must encode 32 bytes. Unchecked if unset.")
	cmd.Flags().BytesHexVar(&cfg.Policy.Measurement, "measurement", []byte{}, "The expected MEASUREMENT field as a hex string. Must encode 48 bytes. Unchecked if unset.")
	cmd.Flags().BytesHexVar(&cfg.Policy.ChipId, "chip_id", []byte{}, "The expected MEASUREMENT field as a hex string. Must encode 48 bytes. Unchecked if unset.")
	cmd.Flags().Uint64Var(&cfg.Policy.MinimumTcb, "minimum_tcb", defaultMinimumTcb, "The minimum acceptable value for CURRENT_TCB, COMMITTED_TCB, and REPORTED_TCB.")
	cmd.Flags().Uint64Var(&cfg.Policy.MinimumLaunchTcb, "minimum_lauch_tcb", defaultMinimumLaunchTcb, "The minimum acceptable value for LAUNCH_TCB.")
	cmd.Flags().Uint32Var(&cfg.Policy.MinimumGuestSvn, "minimum_guest_svn", defaultMinimumGuestSvn, "The most acceptable SnpPolicy.")
	cmd.Flags().Uint32Var(&cfg.Policy.MinimumBuild, "minimum_build", defaultMinimumBuild, "The 8-bit minimum build number for AMD-SP firmware")
	cmd.Flags().BoolVar(&cfg.RootOfTrust.CheckCrl, "check_crl", defaultCheckCrl, "Download and check the CRL for revoked certificates.")
	cmd.Flags().BoolVar(&cfg.RootOfTrust.DisallowNetwork, "disallow_network", defaultDisallowNetwork, "If true, then permitted to download necessary files for verification.")
	cmd.Flags().DurationVar(&timeout, "timeout", defaultTimeout, "Duration to continue to retry failed HTTP requests.")
	cmd.Flags().DurationVar(&maxRetryDelay, "max_retry_delay", defaultMaxRetryDelay, "Maximum Duration to wait between HTTP request retries.")
	cmd.Flags().BoolVar(&cfg.Policy.RequireAuthorKey, "require_author_key", defaultRequireAuthor, "Require that AUTHOR_KEY_EN is 1.")
	cmd.Flags().BoolVar(&cfg.Policy.RequireIdBlock, "require_id_block", defaultRequireIdBlock, "Require that the VM was launch with an ID_BLOCK signed by a trusted id key or author key")
	cmd.Flags().BoolVar(&cfg.Policy.PermitProvisionalFirmware, "permit_provisional_software", defaultPermitProvisionalSoftware, "Permit provisional firmware (i.e., committed values may be less than current values).")
	cmd.Flags().StringVar(&platformInfo, "platform_info", "", "The maximum acceptable PLATFORM_INFO field bit-wise. May be empty or a 64-bit unsigned integer")
	cmd.Flags().StringVar(&cfg.Policy.MinimumVersion, "minimum_version", "", "Minimum AMD-SP firmware API version (major.minor). Each number must be 8-bit non-negative.")
	cmd.Flags().StringArrayVar(&trustedAuthorKeys, "trusted_author_keys", []string{}, "Paths to x.509 certificates of trusted author keys")
	cmd.Flags().StringArrayVar(&trustedAuthorHashes, "trusted_author_key_hashes", []string{}, "Hex-encoded SHA-384 hash values of trusted author keys in AMD public key format")
	cmd.Flags().StringArrayVar(&trustedIdKeys, "trusted_id_keys", []string{}, "Paths to x.509 certificates of trusted author keys")
	cmd.Flags().StringArrayVar(&trustedIdKeyHashes, "trusted_id_key_hashes", []string{}, "Hex-encoded SHA-384 hash values of trusted identity keys in AMD public key format")
	cmd.Flags().StringVar(&cfg.RootOfTrust.Product, "product", "", "The AMD product name for the chip that generated the attestation report.")
	cmd.Flags().StringVar(&stepping, "stepping", "", "The machine stepping for the chip that generated the attestation report. Default unchecked.")
	cmd.Flags().StringArrayVar(&cfg.RootOfTrust.CabundlePaths, "CA_bundles_paths", []string{}, "Paths to CA bundles for the AMD product. Must be in PEM format, ASK, then ARK certificates. If unset, uses embedded root certificates.")
	cmd.Flags().StringArrayVar(&cfg.RootOfTrust.Cabundles, "CA_bundles", []string{}, "PEM format CA bundles for the AMD product. Combined with contents of cabundle_paths.")

	if err := cmd.MarkFlagRequired("report_data"); err != nil {
		log.Fatalf("Failed to mark flag as required: %s", err)
	}
	return cmd
}

func verifyAndValidateAttestation(attestation []byte) error {
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
	if err = validate.SnpAttestation(attestationPB, opts); err != nil {
		return err
	}
	return nil
}

// parseConfig decodes config passed as json for check.Config struct.
// example
// {"rootOfTrust":{"product":"test_product","cabundlePaths":["test_cabundlePaths"],"cabundles":["test_Cabundles"],"checkCrl":true,"disallowNetwork":true},"policy":{"minimumGuestSvn":1,"policy":"1","familyId":"AQIDBAUGBwgJCgsMDQ4PEA==","imageId":"AQIDBAUGBwgJCgsMDQ4PEA==","vmpl":0,"minimumTcb":"1","minimumLaunchTcb":"1","platformInfo":"1","requireAuthorKey":true,"reportData":"J+60aXs8btm8VcGgaJYURGeNCu0FIyWMFXQ7ZUlJDC0FJGJizJsOzDIXgQ75UtPC+Zqe0A3dvnnf5VEeQ61RTg==","measurement":"8s78ewoX7Xkfy1qsgVnkZwLDotD768Nqt6qTL5wtQOxHsLczipKM6bhDmWiHLdP4","hostData":"GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw=","reportId":"GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw=","reportIdMa":"GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw=","chipId":"J+60aXs8btm8VcGgaJYURGeNCu0FIyWMFXQ7ZUlJDC0FJGJizJsOzDIXgQ75UtPC+Zqe0A3dvnnf5VEeQ61RTg==","minimumBuild":1,"minimumVersion":"0.90","permitProvisionalFirmware":true,"requireIdBlock":true,"trustedAuthorKeys":["GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="],"trustedAuthorKeyHashes":["GSvLKpfu59
// Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="],"trustedIdKeys":["GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="],"trustedIdKeyHashes":["GSvLKpfu59Y9QOF6vhq0vQsOIvb4+5O/UOHLGLBTkdw="],"product":{"name":"SEV_PRODUCT_MILAN","stepping":1,"machineStepping":1}}}.
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
	if err := validateFieldLength("chip_id", cfg.Policy.ChipId, size48); err != nil {
		return err
	}
	for _, hash := range cfg.Policy.TrustedAuthorKeyHashes {
		if err := validateFieldLength("trusted_author_key_hash", hash, sha512.Size384); err != nil {
			return err
		}
	}
	for _, hash := range cfg.Policy.TrustedIdKeyHashes {
		if err := validateFieldLength("trusted_id_key_hash", hash, sha512.Size384); err != nil {
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
