// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"fmt"
	"os"
	"path"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/verify/trust"
	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos/pkg/attestation"
)

const (
	caBundleName      = "ask_ark.pem"
	filePermisionKeys = 0o766
)

func (cli *CLI) NewCABundleCmd(fileSavePath string) *cobra.Command {
	return &cobra.Command{
		Use:     "ca-bundle",
		Short:   "Fetch AMD SEV-SNPs CA Bundle (ASK and ARK)",
		Example: "ca-bundle <path_to_platform_info_json>",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			attestationConfiguration := attestation.Config{Config: &check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}}, PcrConfig: &attestation.PcrConfig{}}
			err := attestation.ReadAttestationPolicy(args[0], &attestationConfiguration)
			if err != nil {
				printError(cmd, "Error while reading manifest: %v ❌ ", err)
				return
			}

			product := attestationConfiguration.Config.RootOfTrust.ProductLine

			getter := trust.DefaultHTTPSGetter()
			caURL := kds.ProductCertChainURL(abi.VcekReportSigner, product)

			bundle, err := getter.Get(caURL)
			if err != nil {
				message := fmt.Sprintf("Error fetching ARK and ASK from AMD KDS for product: %s", product)
				message += ", error: %v ❌ "
				printError(cmd, message, err)
				return
			}

			err = os.MkdirAll(path.Join(fileSavePath, product), filePermisionKeys)
			if err != nil {
				message := fmt.Sprintf("Error while creating directory for product name %s", product)
				message += ", error: %v ❌ "
				printError(cmd, message, err)
				return
			}

			bundlePath := path.Join(fileSavePath, product, caBundleName)
			if err = saveToFile(bundlePath, bundle); err != nil {
				printError(cmd, "Error while saving ARK-ASK to file: %v ❌ ", err)
				return
			}
		},
	}
}

func saveToFile(fileSavePath string, content []byte) error {
	file, err := os.OpenFile(fileSavePath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, filePermisionKeys)
	if err != nil {
		return err
	}

	if _, err := file.Write(content); err != nil {
		return err
	}

	return nil
}
