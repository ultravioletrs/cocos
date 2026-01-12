// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package eat

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// CBOREncoder encodes EAT claims to CBOR format (CWT - CBOR Web Token).
type CBOREncoder struct {
	signingKey *ecdsa.PrivateKey
	issuer     string
}

// NewCBOREncoder creates a new CBOR encoder.
func NewCBOREncoder(signingKey *ecdsa.PrivateKey, issuer string) *CBOREncoder {
	return &CBOREncoder{
		signingKey: signingKey,
		issuer:     issuer,
	}
}

// Encode encodes EAT claims to CBOR bytes with COSE_Sign1 signature.
func (e *CBOREncoder) Encode(claims *EATClaims) ([]byte, error) {
	// Set standard CWT claims
	now := time.Now()
	claims.Issuer = e.issuer
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = now.Add(5 * time.Minute).Unix() // 5 minute validity

	// Encode claims to CBOR (this will be the payload)
	payload, err := cbor.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to encode CBOR payload: %w", err)
	}

	// Create COSE Sign1 message
	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmES256)
	msg.Headers.Unprotected[cose.HeaderLabelKeyID] = []byte(e.issuer)

	// Create signer from ECDSA private key
	signer, err := cose.NewSigner(cose.AlgorithmES256, e.signingKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create COSE signer: %w", err)
	}

	// Sign the message
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return nil, fmt.Errorf("failed to sign COSE message: %w", err)
	}

	// Encode the signed message to CBOR
	signed, err := msg.MarshalCBOR()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal COSE_Sign1: %w", err)
	}

	return signed, nil
}

// EncodeToCBOR is a convenience function to encode EAT claims to CBOR.
func EncodeToCBOR(claims *EATClaims, signingKey *ecdsa.PrivateKey, issuer string) ([]byte, error) {
	encoder := NewCBOREncoder(signingKey, issuer)
	return encoder.Encode(claims)
}
