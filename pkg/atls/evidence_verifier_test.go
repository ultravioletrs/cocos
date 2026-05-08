// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package atls

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cocosattestation "github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/eat"
	"github.com/veraison/corim/corim"
)

type stubVerifier struct {
	reports [][]byte
	err     error
}

func (s *stubVerifier) VerifyWithCoRIM(report []byte, _ *corim.UnsignedCorim) error {
	s.reports = append(s.reports, append([]byte(nil), report...))
	return s.err
}

func TestPolicyEvidenceVerifierVerifyEvidence_RootOnly(t *testing.T) {
	root := &stubVerifier{}
	gpu := &stubVerifier{}

	v := &policyEvidenceVerifier{
		policyPath: "/tmp/policy",
		loadManifest: func(string) (*corim.UnsignedCorim, error) {
			return &corim.UnsignedCorim{}, nil
		},
		rootVerifier: func(cocosattestation.PlatformType) (cocosattestation.Verifier, error) {
			return root, nil
		},
		newGPUVerifier: func() (cocosattestation.Verifier, error) {
			return gpu, nil
		},
	}

	err := v.VerifyEvidence(encodeClaims(t, &eat.EATClaims{
		PlatformType: "TDX",
		RawReport:    []byte("root-report"),
		Nonce:        []byte("session-nonce"),
	}))
	require.NoError(t, err)
	assert.Equal(t, [][]byte{[]byte("root-report")}, root.reports)
	assert.Empty(t, gpu.reports)
}

func TestPolicyEvidenceVerifierVerifyEvidence_RootAndGPU(t *testing.T) {
	root := &stubVerifier{}
	gpu := &stubVerifier{}
	sessionNonce := []byte("session-nonce")
	gpuNonce := deriveExpectedGPUNonce(sessionNonce)
	gpuNonceHex := hex.EncodeToString(gpuNonce)
	evidenceJSON := fmt.Appendf(nil, `[{"nonce":"%s","evidence":"abc","certificate":"def"}]`, gpuNonceHex)

	v := &policyEvidenceVerifier{
		policyPath: "/tmp/policy",
		loadManifest: func(string) (*corim.UnsignedCorim, error) {
			return &corim.UnsignedCorim{}, nil
		},
		rootVerifier: func(cocosattestation.PlatformType) (cocosattestation.Verifier, error) {
			return root, nil
		},
		newGPUVerifier: func() (cocosattestation.Verifier, error) {
			return gpu, nil
		},
	}

	err := v.VerifyEvidence(encodeClaims(t, &eat.EATClaims{
		PlatformType: "TDX",
		RawReport:    []byte("root-report"),
		Nonce:        sessionNonce,
		GPUExtensions: &eat.GPUExtensions{
			Nonce:        gpuNonce,
			EvidenceJSON: evidenceJSON,
		},
	}))
	require.NoError(t, err)
	assert.Equal(t, [][]byte{[]byte("root-report")}, root.reports)
	assert.Equal(t, [][]byte{evidenceJSON}, gpu.reports)
}

func TestPolicyEvidenceVerifierVerifyEvidence_GPUNonceMismatch(t *testing.T) {
	root := &stubVerifier{}

	v := &policyEvidenceVerifier{
		policyPath: "/tmp/policy",
		loadManifest: func(string) (*corim.UnsignedCorim, error) {
			return &corim.UnsignedCorim{}, nil
		},
		rootVerifier: func(cocosattestation.PlatformType) (cocosattestation.Verifier, error) {
			return root, nil
		},
	}

	err := v.VerifyEvidence(encodeClaims(t, &eat.EATClaims{
		PlatformType: "TDX",
		RawReport:    []byte("root-report"),
		Nonce:        []byte("session-nonce"),
		GPUExtensions: &eat.GPUExtensions{
			Nonce:        []byte("wrong"),
			EvidenceJSON: []byte(`[{"nonce":"aabbcc"}]`),
		},
	}))
	require.Error(t, err)
	assert.ErrorContains(t, err, "gpu nonce binding mismatch")
	assert.Equal(t, [][]byte{[]byte("root-report")}, root.reports)
}

func TestPolicyEvidenceVerifierVerifyEvidence_GPUVerifierError(t *testing.T) {
	expectedErr := errors.New("gpu verify failed")
	root := &stubVerifier{}
	gpu := &stubVerifier{err: expectedErr}
	sessionNonce := []byte("session-nonce")
	derivedNonce := deriveExpectedGPUNonce(sessionNonce)
	gpuEvidenceJSON := fmt.Appendf(nil, `[{"nonce":"%s"}]`, hex.EncodeToString(derivedNonce))

	v := &policyEvidenceVerifier{
		policyPath: "/tmp/policy",
		loadManifest: func(string) (*corim.UnsignedCorim, error) {
			return &corim.UnsignedCorim{}, nil
		},
		rootVerifier: func(cocosattestation.PlatformType) (cocosattestation.Verifier, error) {
			return root, nil
		},
		newGPUVerifier: func() (cocosattestation.Verifier, error) {
			return gpu, nil
		},
	}

	err := v.VerifyEvidence(encodeClaims(t, &eat.EATClaims{
		PlatformType: "TDX",
		RawReport:    []byte("root-report"),
		Nonce:        sessionNonce,
		GPUExtensions: &eat.GPUExtensions{
			Nonce:        derivedNonce,
			EvidenceJSON: gpuEvidenceJSON,
		},
	}))
	require.Error(t, err)
	assert.ErrorIs(t, err, expectedErr)
}

func encodeClaims(t *testing.T, claims *eat.EATClaims) []byte {
	t.Helper()

	b, err := cbor.Marshal(claims)
	require.NoError(t, err)
	return b
}

func deriveExpectedGPUNonce(sessionNonce []byte) []byte {
	sum := sha256.Sum256(append(append([]byte(nil), sessionNonce...), []byte(":gpu")...))
	return sum[:]
}
