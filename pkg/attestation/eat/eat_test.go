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
