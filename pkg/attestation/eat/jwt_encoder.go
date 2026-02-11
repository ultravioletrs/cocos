// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package eat

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTEncoder encodes EAT claims to JWT format.
type JWTEncoder struct {
	signingKey *ecdsa.PrivateKey
	issuer     string
}

// NewJWTEncoder creates a new JWT encoder.
func NewJWTEncoder(signingKey *ecdsa.PrivateKey, issuer string) *JWTEncoder {
	return &JWTEncoder{
		signingKey: signingKey,
		issuer:     issuer,
	}
}

// Encode encodes EAT claims to JWT string.
func (e *JWTEncoder) Encode(claims *EATClaims) (string, error) {
	// Set standard JWT claims
	now := time.Now()
	claims.Issuer = e.issuer
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = now.Add(5 * time.Minute).Unix() // 5 minute validity

	// Create JWT token with custom claims
	token := jwt.NewWithClaims(jwt.SigningMethodES256, &jwtClaims{claims})

	// Sign the token
	tokenString, err := token.SignedString(e.signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return tokenString, nil
}

// jwtClaims wraps EATClaims for JWT encoding.
type jwtClaims struct {
	*EATClaims
}

// GetExpirationTime implements jwt.Claims interface.
func (c *jwtClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	if c.ExpiresAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.ExpiresAt, 0)), nil
}

// GetIssuedAt implements jwt.Claims interface.
func (c *jwtClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	if c.IssuedAt == 0 {
		return nil, nil
	}
	return jwt.NewNumericDate(time.Unix(c.IssuedAt, 0)), nil
}

// GetNotBefore implements jwt.Claims interface.
func (c *jwtClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return nil, nil
}

// GetIssuer implements jwt.Claims interface.
func (c *jwtClaims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

// GetSubject implements jwt.Claims interface.
func (c *jwtClaims) GetSubject() (string, error) {
	return c.Subject, nil
}

// GetAudience implements jwt.Claims interface.
func (c *jwtClaims) GetAudience() (jwt.ClaimStrings, error) {
	return nil, nil
}

// EncodeToJWT is a convenience function to encode EAT claims to JWT.
func EncodeToJWT(claims *EATClaims, signingKey *ecdsa.PrivateKey, issuer string) (string, error) {
	encoder := NewJWTEncoder(signingKey, issuer)
	return encoder.Encode(claims)
}

// GenerateSigningKey generates a new ECDSA signing key.
func GenerateSigningKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
