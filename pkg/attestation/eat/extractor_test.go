// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package eat

import (
	"encoding/json"
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

func TestTDXExtensionsJSON(t *testing.T) {
	ext := &TDXExtensions{
		MRTD:         []byte("mrtd_val"),
		RTMR0:        []byte("rtmr0_val"),
		RTMR1:        []byte("rtmr1_val"),
		RTMR2:        []byte("rtmr2_val"),
		RTMR3:        []byte("rtmr3_val"),
		XFAM:         123,
		TDAttributes: 456,
		TDXModule: &TDXModuleInfo{
			Major: 1,
		},
	}

	claims := &EATClaims{
		TDXExtensions: ext,
	}

	// Marshal to JSON
	data, err := json.Marshal(claims)
	assert.NoError(t, err)

	// Verify JSON keys match Intel EAT profile
	jsonStr := string(data)
	assert.Contains(t, jsonStr, `"tdx_mrtd":"bXJ0ZF92YWw="`)
	assert.Contains(t, jsonStr, `"tdx_rtmr0":"cnRtcjBfdmFs"`) // base64 of "rtmr0_val"
	assert.Contains(t, jsonStr, `"tdx_rtmr1":"cnRtcjFfdmFs"`)
	assert.Contains(t, jsonStr, `"tdx_rtmr2":"cnRtcjJfdmFs"`)
	assert.Contains(t, jsonStr, `"tdx_rtmr3":"cnRtcjNfdmFs"`)
	assert.Contains(t, jsonStr, `"tdx_xfam":123`)
	assert.Contains(t, jsonStr, `"tdx_td_attributes":456`)
	assert.Contains(t, jsonStr, `"tdx_module":{"major":1,"minor":0,"build_num":0,"build_date":0}`)
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
