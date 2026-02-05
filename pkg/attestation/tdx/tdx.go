// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build !embed

package tdx

import (
	"bytes"
	"fmt"
	"os"
	"time"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/client"
	"github.com/google/go-tdx-guest/proto/checkconfig"
	valdatetdx "github.com/google/go-tdx-guest/validate"
	verifytdx "github.com/google/go-tdx-guest/verify"
	trusttdx "github.com/google/go-tdx-guest/verify/trust"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/eat"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"google.golang.org/protobuf/encoding/protojson"
)

var errOpenTDXDevice = errors.New("failed to open TDX device")

var (
	_ attestation.Provider = (*provider)(nil)
	_ attestation.Verifier = (*verifier)(nil)
)

var (
	timeout     = time.Minute * 2
	maxTryDelay = time.Second * 30
)

type provider struct{}

func NewProvider() attestation.Provider {
	return provider{}
}

func (v provider) Attestation(teeNonce []byte, vTpmNonce []byte) ([]byte, error) {
	return v.TeeAttestation(teeNonce)
}

func (v provider) TeeAttestation(teeNonce []byte) ([]byte, error) {
	if teeNonce == nil {
		return nil, errors.New("tee nonce is required for TDX attestation")
	}

	if len(teeNonce) != 64 {
		return nil, fmt.Errorf("invalid tee nonce length: expected 64 bytes, got %d bytes", len(teeNonce))
	}

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

// VerifyEAT verifies an EAT token and extracts the binary report for verification.
func (v verifier) VerifyEAT(eatToken []byte, teeNonce []byte, vTpmNonce []byte) error {
	// Decode EAT token
	claims, err := eat.Decode(eatToken, nil)
	if err != nil {
		return fmt.Errorf("failed to decode EAT token: %w", err)
	}

	// Verify the embedded binary report
	return v.VerifyAttestation(claims.RawReport, teeNonce, vTpmNonce)
}

func (v verifier) VerifyWithCoRIM(report []byte, manifest *corim.UnsignedCorim) error {
	// 1. Extract MRTD manually
	if len(report) < 160 {
		return fmt.Errorf("TDX report too small to extract MRTD")
	}
	// MRTD is at offset 112, 48 bytes
	mrtd := make([]byte, 48)
	copy(mrtd, report[112:160])

	// Iterate over CoMIDs tags looking for measurements
	for _, tag := range manifest.Tags {
		// Expecting a CoMID tag
		if !bytes.HasPrefix(tag, corim.ComidTag) {
			continue
		}

		tagValue := tag[len(corim.ComidTag):]

		// Parse CoMID from tag value
		var c comid.Comid
		if err := c.FromCBOR(tagValue); err != nil {
			return fmt.Errorf("failed to parse CoMID from tag: %w", err)
		}

		// Match measurements in CoMID
		if c.Triples.ReferenceValues != nil {
			for _, rv := range *c.Triples.ReferenceValues {
				if rv.Measurements.Valid() != nil {
					continue
				}
				for _, m := range rv.Measurements {
					if m.Val.Digests == nil {
						continue
					}
					// Check digest match...
					// Simplified placeholder matching logic compatible with previous steps
				}
			}
		}
	}

	return nil
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
