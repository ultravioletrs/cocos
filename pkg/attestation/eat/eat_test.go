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
