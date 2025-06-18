// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/absmach/magistrala/pkg/errors"
	ccpb "github.com/google/go-tdx-guest/proto/checkconfig"
	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	cfgTDX = &ccpb.Config{
		RootOfTrust: &ccpb.RootOfTrust{},
		Policy:      &ccpb.Policy{HeaderPolicy: &ccpb.HeaderPolicy{}, TdQuoteBodyPolicy: &ccpb.TDQuoteBodyPolicy{}},
	}
	rtmrsS             string
	trustedRootS       string
	errNumberRtmrs     = fmt.Errorf("expected 4 RTMRS values")
	errDecodeRtmrs     = fmt.Errorf("failed to decode RTMRS hex string")
	errTrustedRootPath = fmt.Errorf("trusted root path must be a file, not a directory")
	errNotAFile        = fmt.Errorf("trusted root path must be a file")
)

func addTDXVerificationOptions(cmd *cobra.Command) *cobra.Command {
	cmd.Flags().BytesHexVar(
		&cfgTDX.Policy.HeaderPolicy.QeVendorId,
		"qe_vendor_id",
		[]byte{},
		"The expected QE_VENDOR_ID field as a hex string. Must encode 16 bytes. Unchecked if unset.",
	)
	cmd.Flags().BytesHexVar(
		&cfgTDX.Policy.TdQuoteBodyPolicy.MrSeam,
		"mr_seam",
		[]byte{},
		"The expected MR_SEAM field as a hex string. Must encode 48 bytes. Unchecked if unset.",
	)
	cmd.Flags().BytesHexVar(
		&cfgTDX.Policy.TdQuoteBodyPolicy.TdAttributes,
		"td_attributes",
		[]byte{},
		"The expected TD_ATTRIBUTES field as a hex string. Must encode 8 bytes. Unchecked if unset.",
	)
	cmd.Flags().BytesHexVar(
		&cfgTDX.Policy.TdQuoteBodyPolicy.Xfam,
		"xfam",
		[]byte{},
		"The expected XFAM field as a hex string. Must encode 8 bytes. Unchecked if unset.",
	)
	cmd.Flags().BytesHexVar(
		&cfgTDX.Policy.TdQuoteBodyPolicy.MrTd,
		"mr_td",
		[]byte{},
		"The expected MR_TD field as a hex string. Must encode 48 bytes. Unchecked if unset.",
	)
	cmd.Flags().BytesHexVar(
		&cfgTDX.Policy.TdQuoteBodyPolicy.MrConfigId,
		"mr_config_id",
		[]byte{},
		"The expected MR_CONFIG_ID field as a hex string. Must encode 48 bytes. Unchecked if unset.",
	)
	cmd.Flags().BytesHexVar(
		&cfgTDX.Policy.TdQuoteBodyPolicy.MrOwnerConfig,
		"mr_owner",
		[]byte{},
		"The expected MR_OWNER field as a hex string. Must encode 48 bytes. Unchecked if unset.",
	)
	cmd.Flags().BytesHexVar(
		&cfgTDX.Policy.TdQuoteBodyPolicy.MrOwnerConfig,
		"mr_config_owner",
		[]byte{},
		"The expected MR_OWNER_CONFIG field as a hex string. Must encode 48 bytes. Unchecked if unset.",
	)
	cmd.Flags().BytesHexVar(
		&cfgTDX.Policy.TdQuoteBodyPolicy.MinimumTeeTcbSvn,
		"minimum_tee_tcb_svn",
		[]byte{},
		"The minimum acceptable value for TEE_TCB_SVN field as a hex string. Must encode 16 bytes. Unchecked if unset.",
	)
	cmd.Flags().StringVar(
		&rtmrsS,
		"rtmrs",
		"",
		"Comma-separated hex strings representing expected values of RTMRS field. Expected 4 strings, either empty or each must encode 48 bytes. Unchecked if unset",
	)
	cmd.Flags().StringVar(
		&trustedRootS,
		"trusted_root",
		"",
		"Comma-separated paths to CA bundles for the Intel TDX. Must be in PEM format, Root CA certificate. If unset, uses embedded root certificate.",
	)
	cmd.Flags().Uint32Var(
		&cfgTDX.Policy.HeaderPolicy.MinimumQeSvn,
		"minimum_qe_svn",
		0,
		"The minimum acceptable value for QE_SVN field.",
	)
	cmd.Flags().Uint32Var(
		&cfgTDX.Policy.HeaderPolicy.MinimumPceSvn,
		"minimum_pce_svn",
		0,
		"The minimum acceptable value for PCE_SVN field.",
	)
	cmd.Flags().BoolVar(
		&cfgTDX.RootOfTrust.GetCollateral,
		"get_collateral",
		false,
		"If true, then permitted to download necessary collaterals for additional checks.",
	)

	return cmd
}

func parseRtmrs() ([][]byte, error) {
	if rtmrsS == "" {
		return nil, nil // No RTMRS provided, return nil
	}

	hexString := strings.Split(rtmrsS, ",")
	if len(hexString) != 4 {
		return nil, errNumberRtmrs
	}

	var result [][]byte
	for _, hexStr := range hexString {
		h, err := hex.DecodeString(strings.TrimSpace(hexStr))
		if err != nil {
			return nil, errors.Wrap(errDecodeRtmrs, err)
		}

		result = append(result, h)
	}

	return result, nil
}

func parseTrustedRoot() ([]string, error) {
	if trustedRootS == "" {
		return nil, nil // No trusted roots provided, return nil
	}

	roots := strings.Split(trustedRootS, ",")
	var result []string
	for _, root := range roots {
		p := strings.TrimSpace(root)
		state, err := os.Stat(p)
		if err != nil {
			return nil, errors.Wrap(errTrustedRootPath, err)
		}
		if state.IsDir() {
			return nil, errNotAFile
		}

		result = append(result, p)
	}

	return result, nil
}

func parseTDXConfig() error {
	if cfgString == "" {
		return nil // No config provided, return nil
	}

	policyByte, err := os.ReadFile(cfgString)
	if err != nil {
		return err
	}

	if err := protojson.Unmarshal(policyByte, cfgTDX); err != nil {
		return err
	}

	return nil
}

func validateTDXFlags() error {
	if err := parseTDXConfig(); err != nil {
		return err
	}

	rtrms, err := parseRtmrs()
	if err != nil {
		return err
	}
	if rtrms != nil {
		cfgTDX.Policy.TdQuoteBodyPolicy.Rtmrs = rtrms
	}
	trustedRoots, err := parseTrustedRoot()
	if err != nil {
		return err
	}
	if trustedRoots != nil {
		cfgTDX.RootOfTrust.CabundlePaths = trustedRoots
	}

	if err := validateTDXinput(); err != nil {
		return err
	}

	return nil
}

func tdxVerify(reportFilePath string, provider attestation.Provider) error {
	attestationFile = reportFilePath
	input, err := openInputFile()
	if err != nil {
		return err
	}
	if closer, ok := input.(*os.File); ok {
		defer closer.Close()
	}
	attestationBytes, err := io.ReadAll(input)
	if err != nil {
		return err
	}

	return provider.VerifyAttestation(attestationBytes, reportData, nil)
}

func validateTDXinput() error {
	if err := validateFieldLength("qe_vendor_id", cfgTDX.Policy.HeaderPolicy.QeVendorId, size16); err != nil {
		return err
	}
	if err := validateFieldLength("mr_seam", cfgTDX.Policy.TdQuoteBodyPolicy.MrSeam, size48); err != nil {
		return err
	}
	if err := validateFieldLength("td_attributes", cfgTDX.Policy.TdQuoteBodyPolicy.TdAttributes, size8); err != nil {
		return err
	}
	if err := validateFieldLength("xfam", cfgTDX.Policy.TdQuoteBodyPolicy.Xfam, size8); err != nil {
		return err
	}
	if err := validateFieldLength("mr_td", cfgTDX.Policy.TdQuoteBodyPolicy.MrTd, size48); err != nil {
		return err
	}
	if err := validateFieldLength("mr_config_id", cfgTDX.Policy.TdQuoteBodyPolicy.MrConfigId, size48); err != nil {
		return err
	}
	if err := validateFieldLength("mr_owner", cfgTDX.Policy.TdQuoteBodyPolicy.MrOwnerConfig, size48); err != nil {
		return err
	}
	if err := validateFieldLength("mr_config_owner", cfgTDX.Policy.TdQuoteBodyPolicy.MrOwnerConfig, size48); err != nil {
		return err
	}
	if err := validateFieldLength("minimum_tee_tcb_svn", cfgTDX.Policy.TdQuoteBodyPolicy.MinimumTeeTcbSvn, size16); err != nil {
		return err
	}

	return nil
}
