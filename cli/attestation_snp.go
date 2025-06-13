// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/check"
	tpmAttest "github.com/google/go-tpm-tools/proto/attest"
	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
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
	vtpmFilePath            = "../quote.dat"
	attestationReportJson   = "attestation.json"
	sevProductNameMilan     = "Milan"
	sevProductNameGenoa     = "Genoa"
	FormatBinaryPB          = "binarypb"
	FormatTextProto         = "textproto"
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
	cfg = check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}}
)

func addSEVSNPVerificationOptions(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().BytesHexVar(
		&cfg.Policy.HostData,
		"host_data",
		empty32[:],
		"The expected HOST_DATA field as a hex string. Must encode 32 bytes. Unchecked if unset.",
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
		&checkCrl,
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

	return cmd
}

func validateInput() error {
	if len(cfg.RootOfTrust.CabundlePaths) != 0 || len(cfg.RootOfTrust.Cabundles) != 0 && cfg.RootOfTrust.ProductLine == "" {
		return fmt.Errorf("product name must be set if CA bundles are provided")
	}

	cfg.Policy.ReportData = reportData
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

func parseTrustedKeys() error {
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

func parseAttestationFile() error {
	file, err := os.ReadFile(attestationFile)
	if err != nil {
		return err
	}
	attestationRaw = file
	if isFileJSON(attestationFile) {
		attestationRaw, err = attesationFromJSON(attestationRaw)
		if err != nil {
			return err
		}
	}

	return nil
}

func sevsnpverify(cmd *cobra.Command, provider attestation.Provider, args []string) error {
	cmd.Println("Checking attestation")

	attestationFile = string(args[0])
	if err := parseAttestationFile(); err != nil {
		return fmt.Errorf("error parsing config: %v ❌ ", err)
	}

	// This format is the attestation report in AMD's specified ABI format, immediately
	// followed by the certificate table bytes.
	if len(attestationRaw) < abi.ReportSize {
		return fmt.Errorf("attestation too small: got 0x%x bytes, need at least 0x%x bytes", len(attestationRaw), abi.ReportSize)
	}

	if err := parseAttestationConfig(); err != nil {
		return err
	}

	if err := provider.VerifTeeAttestation(attestationRaw, cfg.Policy.ReportData); err != nil {
		return fmt.Errorf("attestation validation and verification failed with error: %v ❌ ", err)
	}

	cmd.Println("Attestation validation and verification is successful!")
	return nil
}

func parseAttestationConfig() error {
	if err := parseConfig(); err != nil {
		return fmt.Errorf("error parsing config: %v ❌ ", err)
	}
	if err := parseHashes(); err != nil {
		return fmt.Errorf("error parsing hashes: %v ❌ ", err)
	}
	if err := parseTrustedKeys(); err != nil {
		return fmt.Errorf("error parsing files: %v ❌ ", err)
	}

	if err := parseUints(); err != nil {
		return fmt.Errorf("error parsing uints: %v ❌ ", err)
	}

	if err := validateInput(); err != nil {
		return fmt.Errorf("error validating input: %v ❌ ", err)
	}

	return nil
}

func vtpmSevSnpverify(args []string, provider attestation.Provider) error {
	attest, err := returnvTPMAttestation(args)
	if err != nil {
		return err
	}

	if err := parseAttestationConfig(); err != nil {
		return err
	}

	if err := provider.VerifyAttestation(attest, cfg.Policy.ReportData, nonce); err != nil {
		return fmt.Errorf("attestation validation and verification failed with error: %v ❌ ", err)
	}

	return nil
}

func vtpmverify(args []string, provider attestation.Provider) error {
	attestation, err := returnvTPMAttestation(args)
	if err != nil {
		return err
	}

	if err := provider.VerifVTpmAttestation(attestation, nonce); err != nil {
		return fmt.Errorf("attestation validation and verification failed with error: %v ❌ ", err)
	}

	return nil
}

func returnvTPMAttestation(args []string) ([]byte, error) {
	attestationFile = string(args[0])
	input, err := openInputFile()
	if err != nil {
		return nil, err
	}
	if closer, ok := input.(*os.File); ok {
		defer closer.Close()
	}
	attestationBytes, err := io.ReadAll(input)
	if err != nil {
		return nil, err
	}
	attestation := &tpmAttest.Attestation{}

	if format == FormatBinaryPB {
		return attestationBytes, nil
	} else if format == FormatTextProto {
		unmarshalOptions := prototext.UnmarshalOptions{}
		err = unmarshalOptions.Unmarshal(attestationBytes, attestation)
	} else {
		return nil, fmt.Errorf("format should be either binarypb or textproto")
	}
	if err != nil {
		return nil, fmt.Errorf("fail to unmarshal attestation report: %v", err)
	}

	attestationBytes, err = proto.Marshal(attestation)
	if err != nil {
		return nil, fmt.Errorf("fail to marshal vTPM attestation report: %v", err)
	}

	return attestationBytes, nil
}
