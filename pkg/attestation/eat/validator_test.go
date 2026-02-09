// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package eat

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestValidateEATClaims(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name        string
		claims      *EATClaims
		policy      *EATValidationPolicy
		expectedErr string
	}{
		{
			name:   "Nil policy",
			claims: &EATClaims{},
			policy: nil,
		},
		{
			name: "Valid claims conforming to policy",
			claims: &EATClaims{
				Nonce:        []byte("nonce"),
				Measurements: []byte("meas"),
				IssuedAt:     now.Unix(),
				ExpiresAt:    now.Add(time.Hour).Unix(),
			},
			policy: &EATValidationPolicy{
				RequireClaims:      []string{"eat_nonce", "measurements"},
				MaxTokenAgeSeconds: 300,
			},
		},
		{
			name: "Missing nonce",
			claims: &EATClaims{
				Measurements: []byte("meas"),
			},
			policy: &EATValidationPolicy{
				RequireClaims: []string{"eat_nonce"},
			},
			expectedErr: "missing required claim: eat_nonce",
		},
		{
			name: "Missing measurements",
			claims: &EATClaims{
				Nonce: []byte("nonce"),
			},
			policy: &EATValidationPolicy{
				RequireClaims: []string{"measurements"},
			},
			expectedErr: "missing required claim: measurements",
		},
		{
			name:   "Missing platform type",
			claims: &EATClaims{},
			policy: &EATValidationPolicy{
				RequireClaims: []string{"platform_type"},
			},
			expectedErr: "missing required claim: platform_type",
		},
		{
			name:   "Missing UEID",
			claims: &EATClaims{},
			policy: &EATValidationPolicy{
				RequireClaims: []string{"ueid"},
			},
			expectedErr: "missing required claim: ueid",
		},
		{
			name: "Token too old",
			claims: &EATClaims{
				IssuedAt: now.Add(-2 * time.Hour).Unix(),
			},
			policy: &EATValidationPolicy{
				MaxTokenAgeSeconds: 3600, // 1 hour max age
			},
			expectedErr: "token too old",
		},
		{
			name: "Token expired",
			claims: &EATClaims{
				ExpiresAt: now.Add(-1 * time.Hour).Unix(),
			},
			policy:      &EATValidationPolicy{},
			expectedErr: "token expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEATClaims(tt.claims, tt.policy)
			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
