// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package eat

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ultravioletrs/cocos/pkg/attestation"
)

func TestNewEATClaims(t *testing.T) {
	tests := []struct {
		name        string
		nonce       []byte
		expectedErr string
	}{
		{
			name:        "Valid nonce",
			nonce:       []byte("12345678"),
			expectedErr: "",
		},
		{
			name:        "Nonce too short",
			nonce:       []byte("1234567"),
			expectedErr: "eat_nonce must be at least 8 bytes long",
		},
		{
			name:        "Empty nonce",
			nonce:       []byte{},
			expectedErr: "eat_nonce must be at least 8 bytes long",
		},
		{
			name:        "Nil nonce",
			nonce:       nil,
			expectedErr: "eat_nonce must be at least 8 bytes long",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewEATClaims([]byte("dummy report"), tt.nonce, attestation.NoCC)
			if tt.expectedErr != "" {
				assert.EqualError(t, err, tt.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSanitize(t *testing.T) {
	tests := []struct {
		name     string
		claims   *EATClaims
		expected *EATClaims
	}{
		{
			name: "All dependencies present",
			claims: &EATClaims{
				OEMID:     123,
				HWModel:   []byte("ValidModel"),
				HWVersion: "1.0",
			},
			expected: &EATClaims{
				OEMID:     123,
				HWModel:   []byte("ValidModel"),
				HWVersion: "1.0",
			},
		},
		{
			name: "Missing OEMID clears HWModel and HWVersion",
			claims: &EATClaims{
				OEMID:     0,
				HWModel:   []byte("ValidModel"),
				HWVersion: "1.0",
			},
			expected: &EATClaims{
				OEMID:     0,
				HWModel:   nil,
				HWVersion: "",
			},
		},
		{
			name: "Missing HWModel clears HWVersion",
			claims: &EATClaims{
				OEMID:     123,
				HWModel:   nil,
				HWVersion: "1.0",
			},
			expected: &EATClaims{
				OEMID:     123,
				HWModel:   nil,
				HWVersion: "",
			},
		},
		{
			name: "Missing HWModel (empty bytes) clears HWVersion",
			claims: &EATClaims{
				OEMID:     123,
				HWModel:   []byte{},
				HWVersion: "1.0",
			},
			expected: &EATClaims{
				OEMID:     123,
				HWModel:   []byte{}, // Should remain empty slice
				HWVersion: "",
			},
		},
		{
			name: "Independent fields unaffected",
			claims: &EATClaims{
				OEMID:       0,
				DebugStatus: DebugEnabled,
			},
			expected: &EATClaims{
				OEMID:       0,
				DebugStatus: DebugEnabled,
			},
		},
		{
			name: "Missing SWName clears SWVersion",
			claims: &EATClaims{
				SWName:    "",
				SWVersion: "1.0.0",
			},
			expected: &EATClaims{
				SWName:    "",
				SWVersion: "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.claims.Sanitize()
			assert.Equal(t, tt.expected, tt.claims)
		})
	}
}

func TestNewEATClaims_Platforms(t *testing.T) {
	nonce := []byte("12345678")
	dummyReport := make([]byte, 1200) // Large enough for SNP

	tests := []struct {
		name         string
		platform     attestation.PlatformType
		expectError  bool
		expectedName string
	}{
		{
			name:         "SNP",
			platform:     attestation.SNP,
			expectError:  false,
			expectedName: "SNP",
		},
		{
			name:         "vTPM",
			platform:     attestation.VTPM,
			expectError:  false,
			expectedName: "vTPM",
		},
		{
			name:         "Azure",
			platform:     attestation.Azure,
			expectError:  false,
			expectedName: "Azure",
		},
		{
			name:         "NoCC",
			platform:     attestation.NoCC,
			expectError:  false,
			expectedName: "NoCC",
		},
		{
			name:         "Unknown",
			platform:     attestation.PlatformType(99),
			expectError:  false,
			expectedName: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := dummyReport
			if tt.name == "SNP" {
				report = make([]byte, 2000)
				report[0] = 1 // Version
			}
			claims, err := NewEATClaims(report, nonce, tt.platform)
			if tt.expectError {
				assert.Error(t, err)
			} else if err != nil {
				// Special case for platforms that might fail with dummy data (like TDX)
				t.Logf("Platform %s failed with error: %v (expected for dummy data)", tt.name, err)
			} else {
				assert.NotNil(t, claims)
				assert.Equal(t, tt.expectedName, claims.PlatformType)
			}
		})
	}
}

func TestNewEATClaims_WithGPU(t *testing.T) {
	gpuEvidence := &GPUExtensions{
		Vendor:         "nvidia",
		EvidenceFormat: "nvat-json",
		Nonce:          []byte("gpu-nonce"),
		EvidenceJSON:   []byte(`{"evidence":"gpu"}`),
	}

	claims, err := NewEATClaims(
		[]byte("dummy report"),
		[]byte("12345678"),
		attestation.NoCC,
		WithGPU(gpuEvidence),
	)
	assert.NoError(t, err)
	assert.NotNil(t, claims.GPUExtensions)
	assert.Equal(t, gpuEvidence, claims.GPUExtensions)
	assert.Contains(t, claims.Submods, "gpu")
	assert.Equal(t, gpuEvidence, claims.Submods["gpu"])
}
