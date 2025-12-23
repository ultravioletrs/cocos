// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package eat

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/veraison/go-cose"
)

// Decoder decodes EAT tokens (auto-detects JWT vs CBOR).
type Decoder struct {
	verifyKey *ecdsa.PublicKey
}

// NewDecoder creates a new EAT decoder.
func NewDecoder(verifyKey *ecdsa.PublicKey) *Decoder {
	return &Decoder{
		verifyKey: verifyKey,
	}
}

// Decode decodes an EAT token (auto-detects format).
func (d *Decoder) Decode(token []byte) (*EATClaims, error) {
	// Try to detect format
	if isJWT(token) {
		return d.decodeJWT(string(token))
	}
	return d.decodeCBOR(token)
}

// isJWT checks if the token is JWT format.
func isJWT(token []byte) bool {
	// JWT tokens are base64-encoded strings with dots
	return bytes.Contains(token, []byte(".")) && !bytes.Contains(token[:10], []byte{0x00})
}

// decodeJWT decodes a JWT token.
func (d *Decoder) decodeJWT(tokenString string) (*EATClaims, error) {
	claims := &jwtClaims{&EATClaims{}}

	// Parse and verify JWT
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return d.verifyKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid JWT token")
	}

	return claims.EATClaims, nil
}

// decodeCBOR decodes a CBOR token with COSE signature verification.
func (d *Decoder) decodeCBOR(token []byte) (*EATClaims, error) {
	// Try to unmarshal as COSE_Sign1 message
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(token); err != nil {
		// If it's not a COSE message, try to decode as plain CBOR (backward compatibility)
		claims := &EATClaims{}
		if err := cbor.Unmarshal(token, claims); err != nil {
			return nil, fmt.Errorf("failed to decode CBOR: %w", err)
		}
		return claims, nil
	}

	// Verify the signature if we have a verification key
	if d.verifyKey != nil {
		verifier, err := cose.NewVerifier(cose.AlgorithmES256, d.verifyKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create COSE verifier: %w", err)
		}

		if err := msg.Verify(nil, verifier); err != nil {
			return nil, fmt.Errorf("COSE signature verification failed: %w", err)
		}
	}

	// Decode the payload
	claims := &EATClaims{}
	if err := cbor.Unmarshal(msg.Payload, claims); err != nil {
		return nil, fmt.Errorf("failed to decode CBOR payload: %w", err)
	}

	return claims, nil
}

// DecodeJWT is a convenience function to decode JWT EAT token.
func DecodeJWT(tokenString string, verifyKey *ecdsa.PublicKey) (*EATClaims, error) {
	decoder := NewDecoder(verifyKey)
	return decoder.decodeJWT(tokenString)
}

// DecodeCBOR is a convenience function to decode CBOR EAT token.
func DecodeCBOR(token []byte, verifyKey *ecdsa.PublicKey) (*EATClaims, error) {
	decoder := NewDecoder(verifyKey)
	return decoder.decodeCBOR(token)
}

// Decode is a convenience function that auto-detects format.
func Decode(token []byte, verifyKey *ecdsa.PublicKey) (*EATClaims, error) {
	decoder := NewDecoder(verifyKey)
	return decoder.Decode(token)
}

// MarshalJSON implements json.Marshaler for pretty printing.
func (c *EATClaims) MarshalJSON() ([]byte, error) {
	type Alias EATClaims
	return json.Marshal(&struct {
		*Alias
		NonceHex        string `json:"eat_nonce_hex,omitempty"`
		UEIDHex         string `json:"ueid_hex,omitempty"`
		MeasurementsHex string `json:"measurements_hex,omitempty"`
	}{
		Alias:           (*Alias)(c),
		NonceHex:        fmt.Sprintf("%x", c.Nonce),
		UEIDHex:         fmt.Sprintf("%x", c.UEID),
		MeasurementsHex: fmt.Sprintf("%x", c.Measurements),
	})
}
