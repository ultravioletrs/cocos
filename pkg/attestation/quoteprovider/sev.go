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
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/client"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/validate"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"github.com/google/logger"
	"google.golang.org/protobuf/proto"
)

const (
	cocosDirectory        = ".cocos"
	caBundleName          = "ask_ark.pem"
	attestationReportSize = 0x4A0
	reportDataSize        = 64
	sevProductNameMilan   = "Milan"
	sevProductNameGenoa   = "Genoa"
)

var (
	AttConfigurationSEVSNP = check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}}
	timeout                = time.Minute * 2
	maxTryDelay            = time.Second * 30
)

var (
	errProductLine     = errors.New(fmt.Sprintf("product name must be %s or %s", sevProductNameMilan, sevProductNameGenoa))
	errReportSize      = errors.New("attestation report size mismatch")
	errAttVerification = errors.New("attestation verification failed")
	errAttValidation   = errors.New("attestation validation failed")
)

func fillInAttestationLocal(attestation *sevsnp.Attestation) error {
	product := AttConfigurationSEVSNP.RootOfTrust.ProductLine

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

		bundleFilePath := path.Join(homePath, cocosDirectory, product, caBundleName)
		if _, err := os.Stat(bundleFilePath); err == nil {
			amdRootCerts := trust.AMDRootCerts{}
			if err := amdRootCerts.FromKDSCert(bundleFilePath); err != nil {
				return err
			}

			chain.ArkCert = amdRootCerts.ProductCerts.Ark.Raw
			chain.AskCert = amdRootCerts.ProductCerts.Ask.Raw
		}
	}

	return nil
}

func createDeepCopyAttConfig(attConf *check.Config) (*check.Config, error) {
	copy := proto.Clone(attConf).(*check.Config)
	return copy, nil
}

func GetQuoteProvider() (client.QuoteProvider, error) {
	return client.GetQuoteProvider()
}

func VerifyAttestationReportTLS(attestationBytes []byte, reportData []byte) error {
	attestationConfigurationSevSnp, err := createDeepCopyAttConfig(&AttConfigurationSEVSNP)
	if err != nil {
		return fmt.Errorf("failed to create a copy of backend configuration")
	}

	attestationConfigurationSevSnp.Policy.ReportData = reportData[:]
	return VerifyAndValidate(attestationBytes, attestationConfigurationSevSnp)
}

func VerifyAndValidate(attestationReport []byte, cfg *check.Config) error {
	logger.Init("", false, false, io.Discard)

	if len(attestationReport) < attestationReportSize {
		return errReportSize
	}
	attestationBytes := attestationReport[:attestationReportSize]

	// Attestation verification and validation
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

	attestationPB, err := abi.ReportCertsToProto(attestationBytes)
	if err != nil {
		return fmt.Errorf("failed to convert attestation bytes to struct %v", errors.Wrap(errAttVerification, err))
	}

	if err := fillInAttestationLocal(attestationPB); err != nil {
		return fmt.Errorf("failed to fill the attestation with local ARK and ASK certificates %v", err)
	}

	if err = verify.SnpAttestation(attestationPB, sopts); err != nil {
		return errors.Wrap(errAttVerification, err)
	}

	opts, err := validate.PolicyToOptions(cfg.Policy)
	if err != nil {
		return fmt.Errorf("failed to get policy for validation %v", errors.Wrap(errAttVerification, err))
	}

	if err = validate.SnpAttestation(attestationPB, opts); err != nil {
		return errors.Wrap(errAttValidation, err)
	}

	return nil
}

func FetchAttestation(reportDataSlice []byte) ([]byte, error) {
	var reportData [reportDataSize]byte

	qp, err := GetQuoteProvider()
	if err != nil {
		return []byte{}, fmt.Errorf("could not get quote provider")
	}

	if len(reportData) > reportDataSize {
		return []byte{}, fmt.Errorf("attestation report size mismatch")
	}
	copy(reportData[:], reportDataSlice)

	rawQuote, err := qp.GetRawQuote(reportData)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to get raw quote")
	}

	return rawQuote, nil
}
