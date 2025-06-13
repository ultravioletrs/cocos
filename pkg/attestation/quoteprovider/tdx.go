// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build !embed
// +build !embed

package quoteprovider

import (
	"os"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/google/go-tdx-guest/client"
	"github.com/google/go-tdx-guest/proto/checkconfig"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"google.golang.org/protobuf/proto"
)

var (
	errOpenTDXDevice = errors.New("failed to open TDX device")
)

var _ attestation.Provider = (*provider)(nil)

type provider struct {
	policy *checkconfig.Config
}

// {
// 		RootOfTrust: &ccpb.RootOfTrust{},
// 		Policy:      &ccpb.Policy{HeaderPolicy: &ccpb.HeaderPolicy{}, TdQuoteBodyPolicy: &ccpb.TDQuoteBodyPolicy{}},
// 	}

func New(policy *checkconfig.Config) attestation.Provider {
	return provider{policy: policy}
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
	return nil, errors.New("VTPM attestation fetch is not supported")
}

func (v provider) VerifTeeAttestation(report []byte, teeNonce []byte) error {
	return nil
}

func (v provider) VerifVTpmAttestation(report []byte, vTpmNonce []byte) error {
	return errors.New("VTPM attestation verification is not supported")
}

func (v provider) VerifyAttestation(report []byte, teeNonce []byte, vTpmNonce []byte) error {
	return nil
}

func (v provider) AzureAttestationToken(tokenNonce []byte) ([]byte, error) {
	return nil, errors.New("Azure attestation token is not supported")
}

func ReadTDXAttestationPolicy(policyPath string) (*checkconfig.Config, error) {
	policyByte, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, err
	}

	policy := &checkconfig.Config{
		RootOfTrust: &checkconfig.RootOfTrust{},
		Policy:      &checkconfig.Policy{HeaderPolicy: &checkconfig.HeaderPolicy{}, TdQuoteBodyPolicy: &checkconfig.TDQuoteBodyPolicy{}},
	}

	if err := proto.Unmarshal(policyByte, policy); err != nil {
		return nil, err
	}

	return policy, nil
}
