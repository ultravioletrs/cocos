// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package vtpm

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/pkg/attestation/eat"
)

func TestVerifyEAT(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	claims := &eat.EATClaims{
		Nonce:        []byte("test-nonce"),
		IssuedAt:     time.Now().Unix(),
		RawReport:    []byte("dummy-report"), // This will be passed to VerifyAttestation
		PlatformType: "SNP-vTPM",
	}

	jwtEncoder := eat.NewJWTEncoder(key, "issuer")
	token, err := jwtEncoder.Encode(claims)
	require.NoError(t, err)

	writer := &mockWriter{}
	vInterface := NewVerifier(writer)
	v, ok := vInterface.(*verifier)
	require.True(t, ok)

	err = v.VerifyEAT([]byte(token), []byte("tee-nonce"), []byte("vtpm-nonce"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed")
}

func TestVerifyEAT_InvalidToken(t *testing.T) {
	writer := &mockWriter{}
	vInterface := NewVerifier(writer)
	v, ok := vInterface.(*verifier)
	require.True(t, ok)

	err := v.VerifyEAT([]byte("invalid-token"), nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode EAT token")
}

func TestProvider_Methods(t *testing.T) {
	p := NewProvider(true, 1)

	originalExternalTPM := ExternalTPM
	defer func() { ExternalTPM = originalExternalTPM }()

	ExternalTPM = &mockTPM{Buffer: &bytes.Buffer{}}

	_, err := p.VTpmAttestation([]byte("nonce"))
	assert.Error(t, err)

	_, err = p.TeeAttestation([]byte("nonce"))
	assert.Error(t, err)
}
