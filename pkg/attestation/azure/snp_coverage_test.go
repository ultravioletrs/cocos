// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateAttestationPolicy_Success(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	jwk := jose.JSONWebKey{
		Key:          &key.PublicKey,
		KeyID:        "test-kid",
		Algorithm:    "RS256",
		Use:          "sig",
		Certificates: []*x509.Certificate{cert},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwks := jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{jwk},
		}
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	originalMaaURL := MaaURL
	MaaURL = server.URL
	defer func() { MaaURL = originalMaaURL }()

	token := createTestToken(t, key, server.URL)

	policy, err := GenerateAttestationPolicy(token, "Milan", 0)
	require.NoError(t, err)
	require.NotNil(t, policy)
	assert.Equal(t, "SEV_PRODUCT_MILAN", policy.Config.Policy.Product.Name.String())
}

func createTestToken(t *testing.T, key *rsa.PrivateKey, jku string) string {
	claims := jwt.MapClaims{
		"iss": "https://test-issuer.com",
		"aud": "test-audience",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"x-ms-isolation-tee": map[string]any{
			"x-ms-sevsnpvm-familyId":          "0102030405060708090a0b0c0d0e0f10",
			"x-ms-sevsnpvm-imageId":           "0102030405060708090a0b0c0d0e0f10",
			"x-ms-sevsnpvm-launchmeasurement": "0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10",
			"x-ms-sevsnpvm-bootloader-svn":    float64(1),
			"x-ms-sevsnpvm-tee-svn":           float64(2),
			"x-ms-sevsnpvm-snpfw-svn":         float64(3),
			"x-ms-sevsnpvm-microcode-svn":     float64(4),
			"x-ms-sevsnpvm-guestsvn":          float64(5),
			"x-ms-sevsnpvm-idkeydigest":       "0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10",
			"x-ms-sevsnpvm-reportid":          "0102030405060708090a0b0c0d0e0f100102030405060708090a0b0c0d0e0f10",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["jku"] = jku
	token.Header["kid"] = "test-kid"

	signedToken, err := token.SignedString(key)
	require.NoError(t, err)
	return signedToken
}

func TestGenerateAttestationPolicy_InvalidToken(t *testing.T) {
	// Test with invalid token string
	_, err := GenerateAttestationPolicy("invalid-token", "Milan", 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to validate token")
}
