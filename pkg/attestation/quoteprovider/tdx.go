// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build !embed
// +build !embed

package quoteprovider

import (
	"fmt"
	"os"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/client"
	"github.com/google/go-tdx-guest/proto/checkconfig"
	valdatetdx "github.com/google/go-tdx-guest/validate"
	verifytdx "github.com/google/go-tdx-guest/verify"
	trusttdx "github.com/google/go-tdx-guest/verify/trust"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"google.golang.org/protobuf/encoding/protojson"
)

var errOpenTDXDevice = errors.New("failed to open TDX device")

var (
	_ attestation.Provider = (*provider)(nil)
	_ attestation.Verifier = (*verifier)(nil)
)

type provider struct{}

func NewProvider() attestation.Provider {
	return provider{}
}

func (v provider) Attestation(teeNonce []byte, vTpmNonce []byte) ([]byte, error) {
	return v.TeeAttestation(teeNonce)
}

func (v provider) TeeAttestation(teeNonce []byte) ([]byte, error) {
	quoteprovider, err := client.GetQuoteProvider()
	if err != nil {
		return nil, errors.Wrap(err, errOpenTDXDevice)
	}

	return quoteprovider.GetRawQuote([64]byte(teeNonce))
}

func (v provider) VTpmAttestation(vTpmNonce []byte) ([]byte, error) {
	return nil, errors.New("vTPM attestation fetch is not supported")
}

func (v provider) AzureAttestationToken(tokenNonce []byte) ([]byte, error) {
	return nil, errors.New("Azure attestation token is not supported")
}

type verifier struct {
	Policy *checkconfig.Config
}

func NewVerifier() attestation.Verifier {
	Policy := &checkconfig.Config{
		RootOfTrust: &checkconfig.RootOfTrust{},
		Policy:      &checkconfig.Policy{HeaderPolicy: &checkconfig.HeaderPolicy{}, TdQuoteBodyPolicy: &checkconfig.TDQuoteBodyPolicy{}},
	}

	return verifier{
		Policy: Policy,
	}
}

func NewVerifierWithPolicy(policy *checkconfig.Config) attestation.Verifier {
	if policy == nil {
		return NewVerifier()
	}
	return verifier{
		Policy: policy,
	}
}

func (v verifier) VerifTeeAttestation(report []byte, teeNonce []byte) error {
	if v.Policy == nil {
		return fmt.Errorf("tdx policy is not provided")
	}

	quote, err := abi.QuoteToProto(report)
	if err != nil {
		return err
	}

	sopts, err := verifytdx.RootOfTrustToOptions(v.Policy.RootOfTrust)
	if err != nil {
		return err
	}

	sopts.Getter = &trusttdx.RetryHTTPSGetter{
		Timeout:       timeout,
		MaxRetryDelay: maxTryDelay,
		Getter:        &trusttdx.SimpleHTTPSGetter{},
	}

	if err := verifytdx.TdxQuote(quote, sopts); err != nil {
		return err
	}

	opts, err := valdatetdx.PolicyToOptions(v.Policy.Policy)
	if err != nil {
		return err
	}

	if err := valdatetdx.TdxQuote(quote, opts); err != nil {
		return err
	}

	return nil
}

func (v verifier) VerifVTpmAttestation(report []byte, vTpmNonce []byte) error {
	return errors.New("VTPM attestation verification is not supported")
}

func (v verifier) VerifyAttestation(report []byte, teeNonce []byte, vTpmNonce []byte) error {
	return v.VerifTeeAttestation(report, teeNonce)
}

func (v verifier) JSONToPolicy(path string) error {
	return ReadTDXAttestationPolicy(path, v.Policy)
}

func ReadTDXAttestationPolicy(policyPath string, policy *checkconfig.Config) error {
	policyByte, err := os.ReadFile(policyPath)
	if err != nil {
		return err
	}

	if err := protojson.Unmarshal(policyByte, policy); err != nil {
		return err
	}

	return nil
}
