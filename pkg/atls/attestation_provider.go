// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package atls

import (
	"encoding/asn1"
	"fmt"

	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/azure"
	"github.com/ultravioletrs/cocos/pkg/attestation/tdx"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"golang.org/x/crypto/sha3"
)

// AttestationProvider defines the interface for platform attestation operations.
type AttestationProvider interface {
	GetAttestation(pubKey []byte, nonce []byte) ([]byte, error)
	GetOID() asn1.ObjectIdentifier
	GetPlatformType() attestation.PlatformType
}

// PlatformAttestationProvider handles platform attestation operations.
type PlatformAttestationProvider struct {
	provider     attestation.Provider
	oid          asn1.ObjectIdentifier
	platformType attestation.PlatformType
}

// NewAttestationProvider creates a new attestation provider for the given platform type.
func NewAttestationProvider(provider attestation.Provider, platformType attestation.PlatformType) (AttestationProvider, error) {
	oid, err := getOID(platformType)
	if err != nil {
		return nil, fmt.Errorf("failed to get OID: %w", err)
	}

	return &PlatformAttestationProvider{
		provider:     provider,
		oid:          oid,
		platformType: platformType,
	}, nil
}

func (p *PlatformAttestationProvider) GetAttestation(pubKey []byte, nonce []byte) ([]byte, error) {
	teeNonce := append(pubKey, nonce...)
	hashNonce := sha3.Sum512(teeNonce)
	return p.provider.Attestation(hashNonce[:], hashNonce[:32])
}

func (p *PlatformAttestationProvider) GetOID() asn1.ObjectIdentifier {
	return p.oid
}

func (p *PlatformAttestationProvider) GetPlatformType() attestation.PlatformType {
	return p.platformType
}

func getOID(platformType attestation.PlatformType) (asn1.ObjectIdentifier, error) {
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

func getPlatformTypeFromOID(oid asn1.ObjectIdentifier) (attestation.PlatformType, error) {
	switch {
	case oid.Equal(SNPvTPMOID):
		return attestation.SNPvTPM, nil
	case oid.Equal(AzureOID):
		return attestation.Azure, nil
	case oid.Equal(TDXOID):
		return attestation.TDX, nil
	default:
		return 0, fmt.Errorf("unsupported OID: %v", oid)
	}
}

func getPlatformVerifier(platformType attestation.PlatformType) (attestation.Verifier, error) {
	var verifier attestation.Verifier

	switch platformType {
	case attestation.SNPvTPM:
		verifier = vtpm.NewVerifier(nil)
	case attestation.Azure:
		verifier = azure.NewVerifier(nil)
	case attestation.TDX:
		verifier = tdx.NewVerifier()
	default:
		return nil, fmt.Errorf("unsupported platform type: %d", platformType)
	}

	err := verifier.JSONToPolicy(attestation.AttestationPolicyPath)
	if err != nil {
		return nil, err
	}
	return verifier, nil
}
