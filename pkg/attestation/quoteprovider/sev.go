// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build !embed
// +build !embed

package quoteprovider

import (
	"encoding/json"
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
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	cocosDirectory      = ".cocos"
	caBundleName        = "ask_ark.pem"
	Nonce               = 64
	sevProductNameMilan = "Milan"
	sevProductNameGenoa = "Genoa"
)

var (
	timeout                     = time.Minute * 2
	maxTryDelay                 = time.Second * 30
	ErrAttestationPolicyOpen    = errors.New("failed to open Attestation Policy file")
	ErrAttestationPolicyDecode  = errors.New("failed to decode Attestation Policy file")
	ErrAttestationPolicyMissing = errors.New("failed due to missing Attestation Policy file")
	ErrAttestationPolicyEncode  = errors.New("failed to encode the Attestation Policy")
	ErrProtoMarshalFailed       = errors.New("failed to marshal protojson")
	ErrJsonMarshalFailed        = errors.New("failed to marshal json")
	ErrJsonUnarshalFailed       = errors.New("failed to unmarshal json")
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

func verifyReport(attestationPB *sevsnp.Attestation, cfg *check.Config) error {
	sopts, err := verify.RootOfTrustToOptions(cfg.RootOfTrust)
	if err != nil {
		return fmt.Errorf("failed to get root of trust options: %v", errors.Wrap(errAttVerification, err))
	}

	if cfg.Policy.Product == nil {
		productName := GetProductName(cfg.RootOfTrust.ProductLine)
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
		return fmt.Errorf("failed to get policy for validation: %v", errors.Wrap(errAttVerification, err))
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
	attestationConfiguration := attestation.Config{Config: &check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}}, PcrConfig: &attestation.PcrConfig{}}
	err := ReadSEVSNPAttestationPolicy(attestation.AttestationPolicyPath, &attestationConfiguration)
	if err != nil {
		return errors.Wrap(fmt.Errorf("failed to read a attestation policy"), err)
	}
	config := attestationConfiguration.Config

	// Certificate chain is populated based on the extra data that is appended to the SEV-SNP attestation report.
	// This data is not part of the attestation report and it will be ignored.
	attestationPB.CertificateChain = nil

	if len(reportData) != 0 {
		config.Policy.ReportData = reportData[:]
	}

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

func FetchAttestation(reportDataSlice []byte, vmpl uint) ([]byte, error) {
	var reportData [Nonce]byte

	qp, err := GetLeveledQuoteProvider()
	if err != nil {
		return []byte{}, fmt.Errorf("could not get quote provider")
	}

	if len(reportData) > Nonce {
		return []byte{}, fmt.Errorf("attestation report size mismatch")
	}
	copy(reportData[:], reportDataSlice)

	rawQuote, err := qp.GetRawQuoteAtLevel(reportData, vmpl)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to get raw quote")
	}

	return rawQuote, nil
}

func GetProductName(product string) sevsnp.SevProduct_SevProductName {
	switch product {
	case sevProductNameMilan:
		return sevsnp.SevProduct_SEV_PRODUCT_MILAN
	case sevProductNameGenoa:
		return sevsnp.SevProduct_SEV_PRODUCT_GENOA
	default:
		return sevsnp.SevProduct_SEV_PRODUCT_UNKNOWN
	}
}

func ReadSEVSNPAttestationPolicy(policyPath string, attestationConfiguration *attestation.Config) error {
	if policyPath != "" {
		policyData, err := os.ReadFile(policyPath)
		if err != nil {
			return errors.Wrap(ErrAttestationPolicyOpen, err)
		}

		return ReadSEVSNPAttestationPolicyFromByte(policyData, attestationConfiguration)
	}

	return ErrAttestationPolicyMissing
}

func ReadSEVSNPAttestationPolicyFromByte(policyData []byte, attestationConfiguration *attestation.Config) error {
	unmarshalOptions := protojson.UnmarshalOptions{AllowPartial: true, DiscardUnknown: true}

	if err := unmarshalOptions.Unmarshal(policyData, attestationConfiguration.Config); err != nil {
		return errors.Wrap(ErrAttestationPolicyDecode, err)
	}

	if err := json.Unmarshal(policyData, attestationConfiguration.PcrConfig); err != nil {
		return errors.Wrap(ErrAttestationPolicyDecode, err)
	}

	return nil
}

func ConvertSEVSNPAttestationPolicyToJSON(attestationConfiguration *attestation.Config) ([]byte, error) {
	pbJson, err := protojson.Marshal(attestationConfiguration.Config)
	if err != nil {
		return nil, errors.Wrap(ErrProtoMarshalFailed, err)
	}

	var pbMap map[string]interface{}
	if err := json.Unmarshal(pbJson, &pbMap); err != nil {
		return nil, errors.Wrap(ErrJsonUnarshalFailed, err)
	}

	pcrJson, err := json.Marshal(attestationConfiguration.PcrConfig)
	if err != nil {
		return nil, errors.Wrap(ErrJsonMarshalFailed, err)
	}

	var pcrMap map[string]interface{}
	if err := json.Unmarshal(pcrJson, &pcrMap); err != nil {
		return nil, errors.Wrap(ErrJsonUnarshalFailed, err)
	}

	for k, v := range pcrMap {
		pbMap[k] = v
	}

	return json.MarshalIndent(pbMap, "", "  ")
}
