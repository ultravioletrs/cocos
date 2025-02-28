// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build !embed
// +build !embed

package quoteprovider

import (
	"fmt"
	"io"
	"os"
	"path"
	"time"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/google/go-sev-guest/client"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/validate"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"github.com/google/logger"
	config "github.com/ultravioletrs/cocos/pkg/attestation"
	"google.golang.org/protobuf/proto"
)

const (
	cocosDirectory        = ".cocos"
	caBundleName          = "ask_ark.pem"
	attestationReportSize = 0x4A0
	reportDataSize        = 64
	sevProductNameMilan   = "Milan"
	sevProductNameGenoa   = "Genoa"
	sevVMPL               = 2
)

var (
	timeout     = time.Minute * 2
	maxTryDelay = time.Second * 30
)

var (
	errProductLine     = errors.New(fmt.Sprintf("product name must be %s or %s", sevProductNameMilan, sevProductNameGenoa))
	errAttVerification = errors.New("attestation verification failed")
	errAttValidation   = errors.New("attestation validation failed")
)

func fillInAttestationLocal(attestation *sevsnp.Attestation, cfg *check.Config) error {
	product := cfg.RootOfTrust.ProductLine

	chain := attestation.GetCertificateChain()
	if chain == nil {
		chain = &sevsnp.CertificateChain{}
		attestation.CertificateChain = chain
	}
	if len(chain.GetAskCert()) == 0 || len(chain.GetArkCert()) == 0 {
		homePath, err := os.UserHomeDir()
		if err != nil {
			return err
		}

		bundlePath := path.Join(homePath, cocosDirectory, product, caBundleName)
		if _, err := os.Stat(bundlePath); err == nil {
			amdRootCerts := trust.AMDRootCerts{}
			if err := amdRootCerts.FromKDSCert(bundlePath); err != nil {
				return err
			}

			chain.ArkCert = amdRootCerts.ProductCerts.Ark.Raw
			chain.AskCert = amdRootCerts.ProductCerts.Ask.Raw
		}
	}

	return nil
}

func copyConfig(attConf *check.Config) (*check.Config, error) {
	copy := proto.Clone(attConf).(*check.Config)
	return copy, nil
}

func verifyReport(attestationPB *sevsnp.Attestation, cfg *check.Config) error {
	sopts, err := verify.RootOfTrustToOptions(cfg.RootOfTrust)
	if err != nil {
		return fmt.Errorf("failed to get root of trust options: %v", errors.Wrap(errAttVerification, err))
	}

	if cfg.Policy.Product == nil {
		productName := sevsnp.SevProduct_SEV_PRODUCT_UNKNOWN
		switch cfg.RootOfTrust.ProductLine {
		case sevProductNameMilan:
			productName = sevsnp.SevProduct_SEV_PRODUCT_MILAN
		case sevProductNameGenoa:
			productName = sevsnp.SevProduct_SEV_PRODUCT_GENOA
		default:
		}

		if productName == sevsnp.SevProduct_SEV_PRODUCT_UNKNOWN {
			return errProductLine
		}

		sopts.Product = &sevsnp.SevProduct{
			Name: productName,
		}
	} else {
		sopts.Product = cfg.Policy.Product
	}

	sopts.Getter = &trust.RetryHTTPSGetter{
		Timeout:       timeout,
		MaxRetryDelay: maxTryDelay,
		Getter:        &trust.SimpleHTTPSGetter{},
	}

	if err := fillInAttestationLocal(attestationPB, cfg); err != nil {
		return fmt.Errorf("failed to fill the attestation with local ARK and ASK certificates %v", err)
	}

	if err := verify.SnpAttestation(attestationPB, sopts); err != nil {
		return errors.Wrap(errAttVerification, err)
	}

	return nil
}

func validateReport(attestationPB *sevsnp.Attestation, cfg *check.Config) error {
	opts, err := validate.PolicyToOptions(cfg.Policy)
	if err != nil {
		return fmt.Errorf("failed to get policy for validation %v", errors.Wrap(errAttVerification, err))
	}

	if err = validate.SnpAttestation(attestationPB, opts); err != nil {
		return errors.Wrap(errAttValidation, err)
	}

	return nil
}

func GetLeveledQuoteProvider() (client.LeveledQuoteProvider, error) {
	return client.GetLeveledQuoteProvider()
}

func VerifyAttestationReportTLS(attestationPB *sevsnp.Attestation, reportData []byte) error {
	config, err := copyConfig(config.AttestationPolicy.SnpCheck)
	if err != nil {
		return errors.Wrap(fmt.Errorf("failed to create a copy of attestation policy"), err)
	}

	// Certificate chain is populated based on the extra data that is appended to the SEV-SNP attestation report.
	// This data is not part of the attestation report and it will be ignored.
	attestationPB.CertificateChain = nil
	config.Policy.ReportData = reportData[:]
	return VerifyAndValidate(attestationPB, config)
}

func VerifyAndValidate(attestationPB *sevsnp.Attestation, cfg *check.Config) error {
	logger.Init("", false, false, io.Discard)

	if err := verifyReport(attestationPB, cfg); err != nil {
		return err
	}

	if err := validateReport(attestationPB, cfg); err != nil {
		return err
	}

	return nil
}

func FetchAttestation(reportDataSlice []byte) ([]byte, error) {
	var reportData [reportDataSize]byte

	qp, err := GetLeveledQuoteProvider()
	if err != nil {
		return []byte{}, fmt.Errorf("could not get quote provider")
	}

	if len(reportData) > reportDataSize {
		return []byte{}, fmt.Errorf("attestation report size mismatch")
	}
	copy(reportData[:], reportDataSlice)

	rawQuote, err := qp.GetRawQuoteAtLevel(reportData, sevVMPL)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to get raw quote")
	}

	return rawQuote, nil
}
