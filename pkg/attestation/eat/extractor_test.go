// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package eat

import (
	"testing"

	"github.com/google/go-sev-guest/abi"
	"github.com/stretchr/testify/assert"
)

func TestExtractSNPClaims(t *testing.T) {
	tests := []struct {
		name        string
		report      []byte
		expectedErr string
	}{
		{
			name:        "Report too small",
			report:      make([]byte, abi.ReportSize-1),
			expectedErr: "SNP report too small",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &EATClaims{}
			err := extractSNPClaims(claims, tt.report)
			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestExtractTDXClaims(t *testing.T) {
	tests := []struct {
		name        string
		report      []byte
		expectedErr string
	}{
		{
			name:        "Invalid quote",
			report:      []byte("invalid"),
			expectedErr: "failed to parse TDX quote",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &EATClaims{}
			err := extractTDXClaims(claims, tt.report)
			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestExtractVTPMClaims(t *testing.T) {
	report := []byte("dummy vtpm report with enough length")
	claims := &EATClaims{}
	err := extractVTPMClaims(claims, report)
	assert.NoError(t, err)
	assert.Equal(t, report, claims.VTPMExtensions.Quote)
	assert.Equal(t, report[:32], claims.Measurements)
	assert.Equal(t, report[:16], claims.UEID)
}

func TestExtractAzureClaims(t *testing.T) {
	report := []byte("dummy azure report with enough length")
	claims := &EATClaims{}
	err := extractAzureClaims(claims, report)
	assert.NoError(t, err)
	assert.Equal(t, report[:32], claims.Measurements)
	assert.Equal(t, report[:16], claims.UEID)
	assert.Equal(t, int(OEMID_MICROSOFT), claims.OEMID)
}
