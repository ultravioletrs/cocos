// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package atls

import (
	"encoding/asn1"
	"fmt"

	"github.com/ultravioletrs/cocos/pkg/attestation"
	"golang.org/x/crypto/sha3"
)

// AttestationProvider defines the interface for platform attestation operations.
type AttestationProvider interface {
	Attest(pubKey []byte, nonce []byte) ([]byte, error)
	OID() asn1.ObjectIdentifier
	PlatformType() attestation.PlatformType
}

// PlatformAttestationProvider handles platform attestation operations.
type platformAttestationProvider struct {
	provider     attestation.Provider
	oid          asn1.ObjectIdentifier
	platformType attestation.PlatformType
}

// NewAttestationProvider creates a new attestation provider for the given platform type.
func NewAttestationProvider(provider attestation.Provider, platformType attestation.PlatformType) (AttestationProvider, error) {
	oid, err := OID(platformType)
	if err != nil {
		return nil, fmt.Errorf("failed to get OID: %w", err)
	}

	return &platformAttestationProvider{
		provider:     provider,
		oid:          oid,
		platformType: platformType,
	}, nil
}

func (p *platformAttestationProvider) Attest(pubKey []byte, nonce []byte) ([]byte, error) {
	teeNonce := append(pubKey, nonce...)
	hashNonce := sha3.Sum512(teeNonce)
	return p.provider.Attestation(hashNonce[:], hashNonce[:32])
}

func (p *platformAttestationProvider) OID() asn1.ObjectIdentifier {
	return p.oid
}

func (p *platformAttestationProvider) PlatformType() attestation.PlatformType {
	return p.platformType
}

func OID(platformType attestation.PlatformType) (asn1.ObjectIdentifier, error) {
	switch platformType {
	case attestation.SNPvTPM:
		return SNPvTPMOID, nil
	case attestation.Azure:
		return AzureOID, nil
	case attestation.TDX:
		return TDXOID, nil
	default:
		return nil, fmt.Errorf("unsupported platform type: %d", platformType)
	}
}
