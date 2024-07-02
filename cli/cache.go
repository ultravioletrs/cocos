// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"log"
	"os"
	"path"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/verify/trust"
	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos/pkg/clients/grpc"
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
			attestationConfiguration := grpc.AttestationConfiguration{}
			err := grpc.ReadManifest(args[0], &attestationConfiguration)
			if err != nil {
				log.Fatalf("Error while reading manifest: %v", err)
			}

			product := attestationConfiguration.RootOfTrust.Product

			getter := trust.DefaultHTTPSGetter()
			caURL := kds.ProductCertChainURL(abi.VcekReportSigner, product)

			bundle, err := getter.Get(caURL)
			if err != nil {
				log.Fatalf("Error fetching ARK and ASK from AMD KDS for product: %s, error: %v", product, err)
			}

			err = os.MkdirAll(path.Join(fileSavePath, product), filePermisionKeys)
			if err != nil {
				log.Fatalf("Error while creating directory for product name %s, error: %v", product, err)
			}

			bundleFilePath := path.Join(fileSavePath, product, caBundleName)
			if err = saveToFile(bundleFilePath, bundle); err != nil {
				log.Fatalf("Error while saving ARK-ASK to file: %v", err)
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
