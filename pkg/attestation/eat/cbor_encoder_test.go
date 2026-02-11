// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package eat

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

func TestCBOREncoder_Encode(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	type fields struct {
		signingKey *ecdsa.PrivateKey
		issuer     string
	}
	type args struct {
		claims *EATClaims
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Valid encoding",
			fields: fields{
				signingKey: key,
				issuer:     "test-issuer",
			},
			args: args{
				claims: &EATClaims{
					Nonce: []byte("test-nonce"),
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NewCBOREncoder(tt.fields.signingKey, tt.fields.issuer)
			got, err := e.Encode(tt.args.claims)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, got)

				var msg cose.Sign1Message
				err = msg.UnmarshalCBOR(got)
				assert.NoError(t, err)

				verifier, err := cose.NewVerifier(cose.AlgorithmES256, &key.PublicKey)
				assert.NoError(t, err)
				err = msg.Verify(nil, verifier)
				assert.NoError(t, err)
			}
		})
	}
}

func TestEncodeToCBOR(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	claims := &EATClaims{Nonce: []byte("nonce")}
	token, err := EncodeToCBOR(claims, key, "issuer")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}
