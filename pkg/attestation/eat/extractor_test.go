// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package eat

import (
	"fmt"
	"testing"

	"github.com/google/go-sev-guest/abi"
	"github.com/stretchr/testify/assert"
	"github.com/ultravioletrs/cocos/pkg/attestation"
)

func TestExtractSNPClaims(t *testing.T) {
	validReport := make([]byte, abi.ReportSize)
	validReport[0] = 1
	validReport[10] = 0x2 // Policy bit 17 set (byte 2 of Policy, bit 1)

	tests := []struct {
		name        string
		report      []byte
		wantErr     bool
		expectedErr string
	}{
		{
			name:    "valid report size (minimal)",
			report:  validReport,
			wantErr: false,
		},
		{
			name:        "report too small",
			report:      make([]byte, abi.ReportSize-1),
			wantErr:     true,
			expectedErr: "SNP report too small",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &EATClaims{}
			err := extractSNPClaims(claims, tt.report)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.expectedErr != "" {
					assert.Contains(t, err.Error(), tt.expectedErr)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, claims.SNPExtensions)
				assert.Equal(t, OEMID_AMD, claims.OEMID)
				assert.Equal(t, []byte(fmt.Sprintf("SEV-SNP-%d", 1)), claims.HWModel)
			}
		})
	}
}

func TestExtractTDXClaims(t *testing.T) {
	report := []byte("invalid-tdx-quote")
	claims := &EATClaims{}
	err := extractTDXClaims(claims, report)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse TDX quote")
}

func TestExtractVTPMClaims(t *testing.T) {
	report := make([]byte, 32)
	copy(report, []byte("vtpm-report-with-enough-length-123"))

	claims := &EATClaims{}
	err := extractVTPMClaims(claims, report)
	assert.NoError(t, err)
	assert.NotNil(t, claims.VTPMExtensions)
	assert.Equal(t, report, claims.VTPMExtensions.Quote)
	assert.Equal(t, report[:32], claims.Measurements)
	assert.Equal(t, report[:16], claims.UEID)
}

func TestExtractAzureClaims(t *testing.T) {
	report := make([]byte, 32) // Needs at least 32 bytes for valid slicing
	for i := range report {
		report[i] = byte(i)
	}
	claims := &EATClaims{}
	err := extractAzureClaims(claims, report)
	assert.NoError(t, err)
	assert.Equal(t, report, claims.Measurements)
	assert.Equal(t, report[:16], claims.UEID)
	assert.Equal(t, OEMID_MICROSOFT, claims.OEMID)
}

// Platform type helper.
func TestGetPlatformTypeName(t *testing.T) {
	tests := []struct {
		pt   attestation.PlatformType
		want string
	}{
		{attestation.SNP, "SNP"},
		{attestation.SNPvTPM, "SNP-vTPM"},
		{attestation.TDX, "TDX"},
		{attestation.VTPM, "vTPM"},
		{attestation.Azure, "Azure"},
		{attestation.NoCC, "NoCC"},
		{attestation.PlatformType(999), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, getPlatformTypeName(tt.pt))
		})
	}
}
