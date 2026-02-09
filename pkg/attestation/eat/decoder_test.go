// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package eat

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/go-cose"
)

func TestDecodeJWT(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	claims := &EATClaims{
		Nonce: []byte("test-nonce"),
	}

	now := time.Now()
	jwtClaims := &jwtClaims{claims}
	claims.Issuer = "test-issuer"
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = now.Add(time.Hour).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwtClaims)
	signedToken, err := token.SignedString(privateKey)
	require.NoError(t, err)

	type args struct {
		token     string
		verifyKey *ecdsa.PublicKey
	}
	tests := []struct {
		name        string
		args        args
		wantErr     bool
		expectedErr string
	}{
		{
			name: "Valid token",
			args: args{
				token:     signedToken,
				verifyKey: &privateKey.PublicKey,
			},
			wantErr: false,
		},
		{
			name: "Invalid signature",
			args: args{
				token: signedToken,
				verifyKey: func() *ecdsa.PublicKey {
					key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					return &key.PublicKey
				}(),
			},
			wantErr:     true,
			expectedErr: "verification error",
		},
		{
			name: "Malformed token",
			args: args{
				token:     "invalid.token.structure",
				verifyKey: &privateKey.PublicKey,
			},
			wantErr:     true,
			expectedErr: "failed to parse JWT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeJWT(tt.args.token, tt.args.verifyKey)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.expectedErr != "" {
					assert.ErrorContains(t, err, tt.expectedErr)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)
				assert.Equal(t, claims.Nonce, got.Nonce)
			}
		})
	}
}

func TestDecodeCBOR(t *testing.T) {
	claims := &EATClaims{
		Nonce: []byte("test-nonce"),
	}

	payload, err := cbor.Marshal(claims)
	require.NoError(t, err)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := cose.NewSigner(cose.AlgorithmES256, privateKey)
	require.NoError(t, err)

	msg := cose.NewSign1Message()
	msg.Payload = payload
	err = msg.Sign(rand.Reader, []byte{}, signer)
	require.NoError(t, err)

	cborToken, err := msg.MarshalCBOR()
	require.NoError(t, err)

	type args struct {
		token     []byte
		verifyKey *ecdsa.PublicKey
	}
	tests := []struct {
		name        string
		args        args
		wantErr     bool
		expectedErr string
	}{
		{
			name: "Valid COSE token",
			args: args{
				token:     cborToken,
				verifyKey: &privateKey.PublicKey,
			},
			wantErr: false,
		},
		{
			name: "Valid Plain CBOR token (no signature)",
			args: args{
				token:     payload,
				verifyKey: nil,
			},
			wantErr: false,
		},
		{
			name: "Invalid COSE signature",
			args: args{
				token: cborToken,
				verifyKey: func() *ecdsa.PublicKey {
					key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					return &key.PublicKey
				}(),
			},
			wantErr:     true,
			expectedErr: "verification failed",
		},
		{
			name: "Malformed CBOR",
			args: args{
				token:     []byte("invalid cbor"),
				verifyKey: nil,
			},
			wantErr:     true,
			expectedErr: "failed to decode CBOR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeCBOR(tt.args.token, tt.args.verifyKey)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.expectedErr != "" {
					assert.ErrorContains(t, err, tt.expectedErr)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, got)
				assert.Equal(t, claims.Nonce, got.Nonce)
			}
		})
	}
}

func TestDecodeAutoDetect(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	claims := &EATClaims{Nonce: []byte("jwt")}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, &jwtClaims{claims})
	jwtString, _ := token.SignedString(key)

	got, err := Decode([]byte(jwtString), &key.PublicKey)
	assert.NoError(t, err)
	assert.Equal(t, []byte("jwt"), got.Nonce)

	claimsCBOR := &EATClaims{Nonce: []byte("cbor")}
	cborBytes, _ := cbor.Marshal(claimsCBOR)
	gotCBOR, err := Decode(cborBytes, nil)
	assert.NoError(t, err)
	assert.Equal(t, []byte("cbor"), gotCBOR.Nonce)
}

func TestIsJWT(t *testing.T) {
	tests := []struct {
		name  string
		token []byte
		want  bool
	}{
		{"Empty", []byte{}, false},
		{"JWT like", []byte("header.payload.signature"), true},
		{"CBOR (binary)", []byte{0x00, 0x01}, false},
		{"Text but not JWT", []byte("not a jwt"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isJWT(tt.token); got != tt.want {
				t.Errorf("isJWT() = %v, want %v", got, tt.want)
			}
		})
	}
}
