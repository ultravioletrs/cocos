// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package eat

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTEncoder_Encode(t *testing.T) {
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
			e := NewJWTEncoder(tt.fields.signingKey, tt.fields.issuer)
			got, err := e.Encode(tt.args.claims)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, got)

				// Verify the generated token
				parsedToken, err := jwt.ParseWithClaims(got, &jwtClaims{&EATClaims{}}, func(token *jwt.Token) (interface{}, error) {
					return &key.PublicKey, nil
				})
				assert.NoError(t, err)
				assert.True(t, parsedToken.Valid)

				claims, ok := parsedToken.Claims.(*jwtClaims)
				assert.True(t, ok)
				assert.Equal(t, tt.fields.issuer, claims.Issuer)
				assert.Equal(t, tt.args.claims.Nonce, claims.Nonce)
			}
		})
	}
}

func TestGenerateSigningKey(t *testing.T) {
	key, err := GenerateSigningKey()
	assert.NoError(t, err)
	assert.NotNil(t, key)
	assert.Equal(t, elliptic.P256(), key.Curve)
}

func TestEncodeToJWT(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	claims := &EATClaims{Nonce: []byte("nonce")}
	token, err := EncodeToJWT(claims, key, "issuer")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)
}

func TestJwtClaimsINTERFACE(t *testing.T) {
	now := time.Now()
	claims := &EATClaims{
		Issuer:    "iss",
		Subject:   "sub",
		ExpiresAt: now.Add(time.Hour).Unix(),
		IssuedAt:  now.Unix(),
	}
	jwtc := &jwtClaims{claims}

	exp, err := jwtc.GetExpirationTime()
	assert.NoError(t, err)
	assert.Equal(t, claims.ExpiresAt, exp.Unix())

	iat, err := jwtc.GetIssuedAt()
	assert.NoError(t, err)
	assert.Equal(t, claims.IssuedAt, iat.Unix())

	iss, err := jwtc.GetIssuer()
	assert.NoError(t, err)
	assert.Equal(t, claims.Issuer, iss)

	sub, err := jwtc.GetSubject()
	assert.NoError(t, err)
	assert.Equal(t, claims.Subject, sub)

	nbf, err := jwtc.GetNotBefore()
	assert.NoError(t, err)
	assert.Nil(t, nbf)

	aud, err := jwtc.GetAudience()
	assert.NoError(t, err)
	assert.Nil(t, aud)

	// Test zero values
	emptyClaims := &jwtClaims{&EATClaims{}}
	exp, err = emptyClaims.GetExpirationTime()
	assert.NoError(t, err)
	assert.Nil(t, exp)

	iat, err = emptyClaims.GetIssuedAt()
	assert.NoError(t, err)
	assert.Nil(t, iat)
}
