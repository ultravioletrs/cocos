// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	cocosai "github.com/ultravioletrs/cocos"
)

func TestEmptyProvider_Attestation(t *testing.T) {
	tests := []struct {
		name      string
		teeNonce  []byte
		vTpmNonce []byte
		wantErr   bool
	}{
		{
			name:      "should return error for empty nonces",
			teeNonce:  []byte{},
			vTpmNonce: []byte{},
			wantErr:   true,
		},
		{
			name:      "should return error for valid nonces",
			teeNonce:  make([]byte, 64),
			vTpmNonce: make([]byte, 32),
			wantErr:   true,
		},
		{
			name:      "should return error for nil nonces",
			teeNonce:  nil,
			vTpmNonce: nil,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &EmptyProvider{}
			got, err := p.Attestation(tt.teeNonce, tt.vTpmNonce)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, got)
				assert.Contains(t, err.Error(), "EmptyProvider should not be used")
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)
			}
		})
	}
}

func TestEmptyProvider_TeeAttestation(t *testing.T) {
	tests := []struct {
		name     string
		teeNonce []byte
		wantErr  bool
	}{
		{
			name:     "should return error for empty nonce",
			teeNonce: []byte{},
			wantErr:  true,
		},
		{
			name:     "should return error for valid nonce",
			teeNonce: make([]byte, 64),
			wantErr:  true,
		},
		{
			name:     "should return error for nil nonce",
			teeNonce: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &EmptyProvider{}
			got, err := p.TeeAttestation(tt.teeNonce)

			assert.Error(t, err)
			assert.Nil(t, got)
			assert.Contains(t, err.Error(), "EmptyProvider should not be used")
		})
	}
}

func TestEmptyProvider_VTpmAttestation(t *testing.T) {
	tests := []struct {
		name      string
		vTpmNonce []byte
		wantErr   bool
	}{
		{
			name:      "should return embedded attestation for empty nonce",
			vTpmNonce: []byte{},
			wantErr:   false,
		},
		{
			name:      "should return embedded attestation for valid nonce",
			vTpmNonce: make([]byte, 32),
			wantErr:   false,
		},
		{
			name:      "should return embedded attestation for nil nonce",
			vTpmNonce: nil,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &EmptyProvider{}
			got, err := p.VTpmAttestation(tt.vTpmNonce)

			require.NoError(t, err)
			assert.Equal(t, cocosai.EmbeddedAttestation, got)
		})
	}
}

func TestEmptyProvider_AzureAttestationToken(t *testing.T) {
	tests := []struct {
		name    string
		nonce   []byte
		wantErr bool
	}{
		{
			name:    "should return nil for empty nonce",
			nonce:   []byte{},
			wantErr: false,
		},
		{
			name:    "should return nil for valid nonce",
			nonce:   make([]byte, 32),
			wantErr: false,
		},
		{
			name:    "should return nil for nil nonce",
			nonce:   nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &EmptyProvider{}
			got, err := p.AzureAttestationToken(tt.nonce)

			require.NoError(t, err)
			assert.Nil(t, got)
		})
	}
}

func TestEmptyProvider_ImplementsProvider(t *testing.T) {
	var _ Provider = (*EmptyProvider)(nil)
}
