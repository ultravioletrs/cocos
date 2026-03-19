// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"fmt"
	"os"
	"path"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/verify/trust"
	"github.com/spf13/cobra"
)

const (
	caBundleName      = "ask_ark.pem"
	filePermisionKeys = 0o766
)

func (cli *CLI) NewCABundleCmd(fileSavePath string, getter trust.HTTPSGetter) *cobra.Command {
	return &cobra.Command{
		Use:     "ca-bundle",
		Short:   "Fetch AMD SEV-SNPs CA Bundle (ASK and ARK)",
		Example: "ca-bundle <product_name>",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			product := args[0]

			if getter == nil {
				getter = trust.DefaultHTTPSGetter()
			}
			caURL := kds.ProductCertChainURL(abi.VcekReportSigner, product)

			bundle, err := getter.Get(caURL)
			if err != nil {
				return fmt.Errorf("error fetching ARK and ASK from AMD KDS for product %s: %w", product, err)
			}

			err = os.MkdirAll(path.Join(fileSavePath, product), filePermisionKeys)
			if err != nil {
				return fmt.Errorf("error while creating directory for product name %s: %w", product, err)
			}

			bundlePath := path.Join(fileSavePath, product, caBundleName)
			if err = saveToFile(bundlePath, bundle); err != nil {
				return fmt.Errorf("error while saving ARK-ASK to file: %w", err)
			}

			return nil
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
