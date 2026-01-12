// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build !embed

package vtpm

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/google/go-sev-guest/client"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/validate"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"github.com/google/logger"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"google.golang.org/protobuf/proto"
)

const (
	cocosDirectory     = "/cocos"
	arkAskBundleName   = "ask_ark.pem"
	vcekName           = "vcek.pem"
	SEVNonce           = 64
	sevSnpProductMilan = "Milan"
	sevSnpProductGenoa = "Genoa"
)

var (
	timeout     = time.Minute * 2
	maxTryDelay = time.Second * 30
)

var (
	ErrSEVProductLine     = errors.New(fmt.Sprintf("product name must be %s or %s", sevSnpProductMilan, sevSnpProductGenoa))
	ErrSEVAttVerification = errors.New("attestation verification failed")
	errSEVAttValidation   = errors.New("attestation validation failed")
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

		bundlePath := path.Join(homePath, cocosDirectory, product, arkAskBundleName)
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

// verifyReport verifies the SEV-SNP attestation report.
func verifyReport(attestationPB *sevsnp.Attestation, cfg *check.Config) error {
	sopts, err := verify.RootOfTrustToOptions(cfg.RootOfTrust)
	if err != nil {
		return fmt.Errorf("failed to get root of trust options: %v", errors.Wrap(ErrSEVAttVerification, err))
	}

	if cfg.Policy.Product == nil {
		productName := GetSEVProductName(cfg.RootOfTrust.ProductLine)
		if productName == sevsnp.SevProduct_SEV_PRODUCT_UNKNOWN {
			return ErrSEVProductLine
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
		return errors.Wrap(ErrSEVAttVerification, err)
	}

	return nil
}

// validateReport validates the SEV-SNP attestation report against policy.
func validateReport(attestationPB *sevsnp.Attestation, cfg *check.Config) error {
	opts, err := validate.PolicyToOptions(cfg.Policy)
	if err != nil {
		return fmt.Errorf("failed to get policy for validation: %v", errors.Wrap(ErrSEVAttVerification, err))
	}

	if err = validate.SnpAttestation(attestationPB, opts); err != nil {
		return errors.Wrap(errSEVAttValidation, err)
	}

	return nil
}

// getLeveledQuoteProvider returns a leveled quote provider for SEV-SNP.
func getLeveledQuoteProvider() (client.LeveledQuoteProvider, error) {
	return client.GetLeveledQuoteProvider()
}

// VerifySEVAttestationReportTLS verifies a SEV-SNP attestation report for TLS (exported for azure package).
func VerifySEVAttestationReportTLS(attestationPB *sevsnp.Attestation, reportData []byte, policy *attestation.Config) error {
	config := policy.Config

	// Certificate chain is populated based on the extra data that is appended to the SEV-SNP attestation report.
	// This data is not part of the attestation report and it will be ignored.
	attestationPB.CertificateChain = nil

	if len(reportData) != 0 {
		config.Policy.ReportData = reportData[:]
	}

	return verifySEVAndValidate(attestationPB, config)
}

// verifySEVAndValidate performs both verification and validation of a SEV-SNP attestation.
func verifySEVAndValidate(attestationPB *sevsnp.Attestation, cfg *check.Config) error {
	logger.Init("", false, false, io.Discard)

	if err := verifyReport(attestationPB, cfg); err != nil {
		return err
	}

	if err := validateReport(attestationPB, cfg); err != nil {
		return err
	}

	return nil
}

// fetchSEVAttestation fetches a SEV-SNP attestation report.
func fetchSEVAttestation(reportDataSlice []byte, vmpl uint) ([]byte, error) {
	var reportData [SEVNonce]byte

	qp, err := getLeveledQuoteProvider()
	if err != nil {
		return []byte{}, fmt.Errorf("could not get quote provider")
	}

	if len(reportData) > SEVNonce {
		return []byte{}, fmt.Errorf("attestation report size mismatch")
	}
	copy(reportData[:], reportDataSlice)

	quoteProto, err := client.GetQuoteProtoAtLevel(qp, reportData, vmpl)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to get quote proto")
	}

	homePath, _ := os.UserHomeDir()
	vcekPath := path.Join(homePath, cocosDirectory, fmt.Sprintf("%d", quoteProto.Product.Name), vcekName)
	arkAskBundlePath := path.Join(homePath, cocosDirectory, fmt.Sprintf("%d", quoteProto.Product.Name), arkAskBundleName)

	vcekBytes, err := os.ReadFile(vcekPath)
	if err != nil {
		return []byte{}, fmt.Errorf("could not read VCEK file: %v", err)
	}

	arkAskBundleBytes, err := os.ReadFile(arkAskBundlePath)
	if err != nil {
		return []byte{}, fmt.Errorf("could not read ask/ark bundle file: %v", err)
	}

	vcekPem, _ := pem.Decode(vcekBytes)
	arkPem, rest := pem.Decode(arkAskBundleBytes)
	askPem, _ := pem.Decode(rest)

	quoteProto.CertificateChain.VcekCert = vcekPem.Bytes
	quoteProto.CertificateChain.AskCert = askPem.Bytes
	quoteProto.CertificateChain.ArkCert = arkPem.Bytes

	result, err := proto.Marshal(quoteProto)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to marshal quote proto: %v", err)
	}

	return result, nil
}

// GetSEVProductName maps a product string to a SEV product name.
func GetSEVProductName(product string) sevsnp.SevProduct_SevProductName {
	switch product {
	case sevSnpProductMilan:
		return sevsnp.SevProduct_SEV_PRODUCT_MILAN
	case sevSnpProductGenoa:
		return sevsnp.SevProduct_SEV_PRODUCT_GENOA
	default:
		return sevsnp.SevProduct_SEV_PRODUCT_UNKNOWN
	}
}

// derToPem converts DER-encoded certificate to PEM format.
func derToPem(der []byte) []byte {
	// Try to parse to make sure it's a certificate
	if _, err := x509.ParseCertificate(der); err != nil {
		// cert_chain endpoint already returns PEM; just pass through
		return der
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// FetchSEVCertificates fetches SEV-SNP certificates from KDS.
func FetchSEVCertificates(vmpl uint) error {
	var reportData [SEVNonce]byte

	qp, err := getLeveledQuoteProvider()
	if err != nil {
		return fmt.Errorf("could not get quote provider")
	}

	if len(reportData) > SEVNonce {
		return fmt.Errorf("attestation report size mismatch")
	}

	_, err = rand.Read(reportData[:])
	if err != nil {
		return fmt.Errorf("failed to read random data: %v", err)
	}

	quoteProto, err := client.GetQuoteProtoAtLevel(qp, reportData, vmpl) // for coverage
	if err != nil {
		return fmt.Errorf("failed to get quote proto")
	}

	options := &verify.Options{
		CheckRevocations:    true,
		DisableCertFetching: false,
		Getter:              trust.DefaultHTTPSGetter(),
		Now:                 time.Now(),
		TrustedRoots:        nil,
		Product:             quoteProto.Product,
	}

	result, err := verify.GetAttestationFromReport(quoteProto.Report, options)
	if err != nil {
		return fmt.Errorf("could not get fetch certificates: %v", err)
	}

	homePath, _ := os.UserHomeDir()

	vcekPath := path.Join(homePath, cocosDirectory, fmt.Sprintf("%d", quoteProto.Product.Name), vcekName)
	arkAskBundlePath := path.Join(homePath, cocosDirectory, fmt.Sprintf("%d", quoteProto.Product.Name), arkAskBundleName)

	vcekPem := derToPem(result.CertificateChain.VcekCert)
	askPem := derToPem(result.CertificateChain.AskCert)
	arkPem := derToPem(result.CertificateChain.ArkCert)

	arkAskBundlePem := append(askPem, arkPem...)

	vcekDir := filepath.Dir(vcekPath)
	err = os.MkdirAll(vcekDir, 0o755)
	if err != nil {
		return fmt.Errorf("could not create VCEK directory: %v", err)
	}
	askArkBundleDir := filepath.Dir(arkAskBundlePath)
	err = os.MkdirAll(askArkBundleDir, 0o755)
	if err != nil {
		return fmt.Errorf("could not create ask/ark bundle directory: %v", err)
	}

	err = os.WriteFile(vcekPath, vcekPem, 0o644)
	if err != nil {
		return fmt.Errorf("could not write VCEK file: %v", err)
	}

	err = os.WriteFile(arkAskBundlePath, arkAskBundlePem, 0o644)
	if err != nil {
		return fmt.Errorf("could not write ark/ask bundle file: %v", err)
	}

	return nil
}
