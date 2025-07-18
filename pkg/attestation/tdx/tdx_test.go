// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package tdx

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-tdx-guest/proto/checkconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestNewProvider(t *testing.T) {
	tests := []struct {
		name string
		want attestation.Provider
	}{
		{
			name: "should create new provider successfully",
			want: provider{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewProvider()
			assert.IsType(t, tt.want, got)
		})
	}
}

func TestProvider_Attestation(t *testing.T) {
	tests := []struct {
		name        string
		teeNonce    []byte
		vTpmNonce   []byte
		wantErr     bool
		errContains string
	}{
		{
			name:        "should handle empty nonces",
			teeNonce:    []byte{},
			vTpmNonce:   []byte{},
			wantErr:     true,
			errContains: "invalid tee nonce length: expected 64 bytes, got 0 bytes",
		},
		{
			name:        "should handle valid nonces",
			teeNonce:    []byte("test-noncetest-noncetest-noncetest-noncetest-noncetest-noncetest"),
			vTpmNonce:   []byte("vtpm-nonce"),
			wantErr:     true,
			errContains: "/sys/kernel/config/tsm/report",
		},
		{
			name:        "should handle nil nonces",
			teeNonce:    nil,
			vTpmNonce:   nil,
			wantErr:     true,
			errContains: "tee nonce is required for TDX attestation",
		},
		{
			name:        "should handle large nonce",
			teeNonce:    make([]byte, 64),
			vTpmNonce:   make([]byte, 32),
			wantErr:     true,
			errContains: "/sys/kernel/config/tsm/report",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := provider{}
			got, err := p.Attestation(tt.teeNonce, tt.vTpmNonce)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)
			}
		})
	}
}

func TestProvider_TeeAttestation(t *testing.T) {
	tests := []struct {
		name        string
		teeNonce    []byte
		wantErr     bool
		errContains string
	}{
		{
			name:        "should handle empty nonce",
			teeNonce:    []byte{},
			wantErr:     true,
			errContains: "invalid tee nonce length: expected 64 bytes, got 0 bytes",
		},
		{
			name:        "should handle valid nonce",
			teeNonce:    []byte("test-noncetest-noncetest-noncetest-noncetest-noncetest-noncetest"),
			wantErr:     true,
			errContains: "/sys/kernel/config/tsm/report:",
		},
		{
			name:        "should handle nil nonce",
			teeNonce:    nil,
			wantErr:     true,
			errContains: "tee nonce is required for TDX attestation",
		},
		{
			name:        "should handle 64-byte nonce",
			teeNonce:    make([]byte, 64),
			wantErr:     true,
			errContains: "/sys/kernel/config/tsm/report",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := provider{}
			got, err := p.TeeAttestation(tt.teeNonce)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Nil(t, got)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)
			}
		})
	}
}

func TestProvider_VTpmAttestation(t *testing.T) {
	tests := []struct {
		name        string
		vTpmNonce   []byte
		wantErr     bool
		errContains string
	}{
		{
			name:        "should return error for empty nonce",
			vTpmNonce:   []byte{},
			wantErr:     true,
			errContains: "vTPM attestation fetch is not supported",
		},
		{
			name:        "should return error for valid nonce",
			vTpmNonce:   []byte("vtpm-nonce"),
			wantErr:     true,
			errContains: "vTPM attestation fetch is not supported",
		},
		{
			name:        "should return error for nil nonce",
			vTpmNonce:   nil,
			wantErr:     true,
			errContains: "vTPM attestation fetch is not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := provider{}
			got, err := p.VTpmAttestation(tt.vTpmNonce)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
			assert.Nil(t, got)
		})
	}
}

func TestProvider_AzureAttestationToken(t *testing.T) {
	tests := []struct {
		name        string
		tokenNonce  []byte
		wantErr     bool
		errContains string
	}{
		{
			name:        "should return error for empty nonce",
			tokenNonce:  []byte{},
			wantErr:     true,
			errContains: "Azure attestation token is not supported",
		},
		{
			name:        "should return error for valid nonce",
			tokenNonce:  []byte("token-nonce"),
			wantErr:     true,
			errContains: "Azure attestation token is not supported",
		},
		{
			name:        "should return error for nil nonce",
			tokenNonce:  nil,
			wantErr:     true,
			errContains: "Azure attestation token is not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := provider{}
			got, err := p.AzureAttestationToken(tt.tokenNonce)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
			assert.Nil(t, got)
		})
	}
}

func TestNewVerifier(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "should create new verifier successfully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewVerifier()
			v, ok := got.(verifier)
			assert.True(t, ok)
			assert.NotNil(t, v.Policy)
			assert.NotNil(t, v.Policy.RootOfTrust)
			assert.NotNil(t, v.Policy.Policy)
			assert.NotNil(t, v.Policy.Policy.HeaderPolicy)
			assert.NotNil(t, v.Policy.Policy.TdQuoteBodyPolicy)
		})
	}
}

func TestNewVerifierWithPolicy(t *testing.T) {
	tests := []struct {
		name   string
		policy *checkconfig.Config
	}{
		{
			name:   "should create verifier with nil policy",
			policy: nil,
		},
		{
			name: "should create verifier with valid policy",
			policy: &checkconfig.Config{
				RootOfTrust: &checkconfig.RootOfTrust{},
				Policy:      &checkconfig.Policy{},
			},
		},
		{
			name:   "should create verifier with empty policy",
			policy: &checkconfig.Config{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewVerifierWithPolicy(tt.policy)
			v, ok := got.(verifier)
			assert.True(t, ok)

			if tt.policy == nil {
				assert.NotNil(t, v.Policy)
				assert.NotNil(t, v.Policy.RootOfTrust)
				assert.NotNil(t, v.Policy.Policy)
			} else {
				assert.Equal(t, tt.policy, v.Policy)
			}
		})
	}
}

func TestVerifier_VerifTeeAttestation(t *testing.T) {
	tests := []struct {
		name        string
		verifier    verifier
		report      []byte
		teeNonce    []byte
		wantErr     bool
		errContains string
	}{
		{
			name: "should return error when policy is nil",
			verifier: verifier{
				Policy: nil,
			},
			report:      []byte("test-report"),
			teeNonce:    []byte("test-nonce"),
			wantErr:     true,
			errContains: "tdx policy is not provided",
		},
		{
			name: "should handle invalid report format",
			verifier: verifier{
				Policy: &checkconfig.Config{
					RootOfTrust: &checkconfig.RootOfTrust{},
					Policy:      &checkconfig.Policy{},
				},
			},
			report:      []byte("invalid-report"),
			teeNonce:    []byte("test-nonce"),
			wantErr:     true,
			errContains: "",
		},
		{
			name: "should handle empty report",
			verifier: verifier{
				Policy: &checkconfig.Config{
					RootOfTrust: &checkconfig.RootOfTrust{},
					Policy:      &checkconfig.Policy{},
				},
			},
			report:      []byte{},
			teeNonce:    []byte("test-nonce"),
			wantErr:     true,
			errContains: "",
		},
		{
			name: "should handle nil report",
			verifier: verifier{
				Policy: &checkconfig.Config{
					RootOfTrust: &checkconfig.RootOfTrust{},
					Policy:      &checkconfig.Policy{},
				},
			},
			report:      nil,
			teeNonce:    []byte("test-nonce"),
			wantErr:     true,
			errContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.verifier.VerifTeeAttestation(tt.report, tt.teeNonce)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVerifier_VerifVTpmAttestation(t *testing.T) {
	tests := []struct {
		name        string
		verifier    verifier
		report      []byte
		vTpmNonce   []byte
		wantErr     bool
		errContains string
	}{
		{
			name:        "should return error for any input",
			verifier:    verifier{},
			report:      []byte("test-report"),
			vTpmNonce:   []byte("test-nonce"),
			wantErr:     true,
			errContains: "VTPM attestation verification is not supported",
		},
		{
			name:        "should return error for empty inputs",
			verifier:    verifier{},
			report:      []byte{},
			vTpmNonce:   []byte{},
			wantErr:     true,
			errContains: "VTPM attestation verification is not supported",
		},
		{
			name:        "should return error for nil inputs",
			verifier:    verifier{},
			report:      nil,
			vTpmNonce:   nil,
			wantErr:     true,
			errContains: "VTPM attestation verification is not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.verifier.VerifVTpmAttestation(tt.report, tt.vTpmNonce)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.errContains)
		})
	}
}

func TestVerifier_VerifyAttestation(t *testing.T) {
	tests := []struct {
		name        string
		verifier    verifier
		report      []byte
		teeNonce    []byte
		vTpmNonce   []byte
		wantErr     bool
		errContains string
	}{
		{
			name: "should delegate to VerifTeeAttestation with nil policy",
			verifier: verifier{
				Policy: nil,
			},
			report:      []byte("test-report"),
			teeNonce:    []byte("test-nonce"),
			vTpmNonce:   []byte("vtpm-nonce"),
			wantErr:     true,
			errContains: "tdx policy is not provided",
		},
		{
			name: "should delegate to VerifTeeAttestation with valid policy",
			verifier: verifier{
				Policy: &checkconfig.Config{
					RootOfTrust: &checkconfig.RootOfTrust{},
					Policy:      &checkconfig.Policy{},
				},
			},
			report:      []byte("invalid-report"),
			teeNonce:    []byte("test-nonce"),
			vTpmNonce:   []byte("vtpm-nonce"),
			wantErr:     true,
			errContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.verifier.VerifyAttestation(tt.report, tt.teeNonce, tt.vTpmNonce)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVerifier_JSONToPolicy(t *testing.T) {
	tempDir := t.TempDir()

	testPolicy := &checkconfig.Config{
		RootOfTrust: &checkconfig.RootOfTrust{},
		Policy: &checkconfig.Policy{
			HeaderPolicy:      &checkconfig.HeaderPolicy{},
			TdQuoteBodyPolicy: &checkconfig.TDQuoteBodyPolicy{},
		},
	}

	validPolicyJSON, err := protojson.Marshal(testPolicy)
	require.NoError(t, err)

	validPolicyFile := filepath.Join(tempDir, "valid_policy.json")
	err = os.WriteFile(validPolicyFile, validPolicyJSON, 0o644)
	require.NoError(t, err)

	invalidPolicyFile := filepath.Join(tempDir, "invalid_policy.json")
	err = os.WriteFile(invalidPolicyFile, []byte("invalid json"), 0o644)
	require.NoError(t, err)

	tests := []struct {
		name        string
		verifier    verifier
		path        string
		wantErr     bool
		errContains string
	}{
		{
			name: "should load valid policy file",
			verifier: verifier{
				Policy: &checkconfig.Config{},
			},
			path:    validPolicyFile,
			wantErr: false,
		},
		{
			name: "should return error for non-existent file",
			verifier: verifier{
				Policy: &checkconfig.Config{},
			},
			path:        filepath.Join(tempDir, "non_existent.json"),
			wantErr:     true,
			errContains: "no such file or directory",
		},
		{
			name: "should return error for invalid JSON",
			verifier: verifier{
				Policy: &checkconfig.Config{},
			},
			path:        invalidPolicyFile,
			wantErr:     true,
			errContains: "",
		},
		{
			name: "should return error for empty path",
			verifier: verifier{
				Policy: &checkconfig.Config{},
			},
			path:        "",
			wantErr:     true,
			errContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.verifier.JSONToPolicy(tt.path)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReadTDXAttestationPolicy(t *testing.T) {
	tempDir := t.TempDir()

	testPolicy := &checkconfig.Config{
		RootOfTrust: &checkconfig.RootOfTrust{},
		Policy: &checkconfig.Policy{
			HeaderPolicy:      &checkconfig.HeaderPolicy{},
			TdQuoteBodyPolicy: &checkconfig.TDQuoteBodyPolicy{},
		},
	}

	validPolicyJSON, err := protojson.Marshal(testPolicy)
	require.NoError(t, err)

	validPolicyFile := filepath.Join(tempDir, "valid_policy.json")
	err = os.WriteFile(validPolicyFile, validPolicyJSON, 0o644)
	require.NoError(t, err)

	invalidPolicyFile := filepath.Join(tempDir, "invalid_policy.json")
	err = os.WriteFile(invalidPolicyFile, []byte("invalid json"), 0o644)
	require.NoError(t, err)

	emptyFile := filepath.Join(tempDir, "empty.json")
	err = os.WriteFile(emptyFile, []byte{}, 0o644)
	require.NoError(t, err)

	tests := []struct {
		name        string
		policyPath  string
		policy      *checkconfig.Config
		wantErr     bool
		errContains string
	}{
		{
			name:       "should read valid policy file",
			policyPath: validPolicyFile,
			policy:     &checkconfig.Config{},
			wantErr:    false,
		},
		{
			name:        "should return error for non-existent file",
			policyPath:  filepath.Join(tempDir, "non_existent.json"),
			policy:      &checkconfig.Config{},
			wantErr:     true,
			errContains: "no such file or directory",
		},
		{
			name:        "should return error for invalid JSON",
			policyPath:  invalidPolicyFile,
			policy:      &checkconfig.Config{},
			wantErr:     true,
			errContains: "",
		},
		{
			name:        "should return error for empty file",
			policyPath:  emptyFile,
			policy:      &checkconfig.Config{},
			wantErr:     true,
			errContains: "",
		},
		{
			name:        "should return error for empty path",
			policyPath:  "",
			policy:      &checkconfig.Config{},
			wantErr:     true,
			errContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ReadTDXAttestationPolicy(tt.policyPath, tt.policy)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tt.policy)
			}
		})
	}
}
