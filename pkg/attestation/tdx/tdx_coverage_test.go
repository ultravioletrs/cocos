// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package tdx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/pkg/attestation/eat"
)

func TestVerifyEAT_TDX(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	claims := &eat.EATClaims{
		Nonce:        []byte("test-nonce"),
		IssuedAt:     time.Now().Unix(),
		RawReport:    []byte("dummy-report"),
		PlatformType: "TDX",
	}

	jwtEncoder := eat.NewJWTEncoder(key, "issuer")
	token, err := jwtEncoder.Encode(claims)
	require.NoError(t, err)

	vInterface := NewVerifier()

	v, ok := vInterface.(verifier)
	require.True(t, ok)

	err = v.VerifyEAT([]byte(token), []byte("tee-nonce"), []byte("vtpm-nonce"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed")
}

func TestVerifyEAT_TDX_InvalidToken(t *testing.T) {
	vInterface := NewVerifier()
	v, ok := vInterface.(verifier)
	require.True(t, ok)

	err := v.VerifyEAT([]byte("invalid-token"), nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode EAT token")
}

func TestTeeAttestation_InvalidNonce(t *testing.T) {
	p := NewProvider()

	nonce := make([]byte, 64)
	_, err := p.TeeAttestation(nonce)
	assert.Error(t, err)
	// Check for likely errors in non-TDX environment
	errMsg := err.Error()
	assert.True(t,
		assert.Contains(t, errMsg, "no such file or directory") ||
			assert.Contains(t, errMsg, "permission denied") ||
			assert.Contains(t, errMsg, "failed to open TDX device"),
		"unexpected error message: %s", errMsg,
	)
}
