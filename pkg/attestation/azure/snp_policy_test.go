// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"bytes"
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

func TestGenerateAttestationPolicy(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	tests := []struct {
		name          string
		token         string
		product       string
		policy        uint64
		setupServer   func(t *testing.T, key *rsa.PrivateKey, cert *x509.Certificate) *httptest.Server
		wantErr       bool
		errorMessage  string
		setupTokenJKU bool
	}{
		{
			name:    "valid token and claims",
			product: "Milan-B0",
			policy:  0,
			setupServer: func(t *testing.T, key *rsa.PrivateKey, cert *x509.Certificate) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case openIDConfigPath:
						config := map[string]any{
							"jwks_uri": "http://" + r.Host + certsPath,
						}
						w.Header().Set("Content-Type", "application/json")
						if err := json.NewEncoder(w).Encode(config); err != nil {
							t.Errorf("failed to encode config: %v", err)
						}
					case certsPath:
						jwks := generateJWKS(&key.PublicKey, cert)
						w.Header().Set("Content-Type", "application/json")
						if err := json.NewEncoder(w).Encode(jwks); err != nil {
							t.Errorf("failed to encode jwks: %v", err)
						}
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				}))
			},
			setupTokenJKU: true,
			wantErr:       false,
		},
		{
			name:          "invalid token format",
			token:         "invalid-token",
			product:       "Milan-B0",
			policy:        0,
			setupServer:   nil,
			wantErr:       true,
			errorMessage:  "failed to parse token",
			setupTokenJKU: false,
		},
		{
			name:    "missing familyId",
			product: "Milan-B0",
			policy:  0,
			setupServer: func(t *testing.T, key *rsa.PrivateKey, cert *x509.Certificate) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case openIDConfigPath:
						config := map[string]any{
							"jwks_uri": "http://" + r.Host + certsPath,
						}
						w.Header().Set("Content-Type", "application/json")
						if err := json.NewEncoder(w).Encode(config); err != nil {
							t.Errorf("failed to encode config: %v", err)
						}
					case certsPath:
						jwks := generateJWKS(&key.PublicKey, cert)
						w.Header().Set("Content-Type", "application/json")
						if err := json.NewEncoder(w).Encode(jwks); err != nil {
							t.Errorf("failed to encode jwks: %v", err)
						}
					}
				}))
			},
			setupTokenJKU: true,
			wantErr:       true,
			errorMessage:  "failed to get familyId from claims",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tokenString string
			var server *httptest.Server

			if tt.setupServer != nil {
				server = tt.setupServer(t, privateKey, cert)
				defer server.Close()

				originalURL := MaaURL
				MaaURL = "" // Clear it so it uses JKU
				defer func() { MaaURL = originalURL }()
			}

			if tt.token != "" {
				tokenString = tt.token
			} else {
				// Generate token
				claims := createValidClaims()
				if tt.name == "missing familyId" {
					if tee, ok := claims["x-ms-isolation-tee"].(map[string]any); ok {
						delete(tee, "x-ms-sevsnpvm-familyId")
					}
				}

				jku := ""
				if tt.setupTokenJKU && server != nil {
					jku = server.URL
				}

				var err error
				tokenString, err = signToken(claims, privateKey, jku)
				require.NoError(t, err)
			}

			config, err := GenerateAttestationPolicy(tokenString, tt.product, tt.policy)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errorMessage != "" {
					assert.Contains(t, err.Error(), tt.errorMessage)
				}
				assert.Nil(t, config)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, config)
			}
		})
	}
}

func TestVerifier_VerifyEAT(t *testing.T) {
	tests := []struct {
		name         string
		eatToken     []byte
		teeNonce     []byte
		vTpmNonce    []byte
		setupToken   func() ([]byte, error)
		wantErr      bool
		errorMessage string
	}{
		{
			name:      "invalid cbor",
			eatToken:  []byte("invalid-cbor"),
			teeNonce:  testNonce,
			vTpmNonce: testNonce,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewVerifier(&bytes.Buffer{})

			token := tt.eatToken
			if tt.setupToken != nil {
				var err error
				token, err = tt.setupToken()
				require.NoError(t, err)
			}

			err := v.VerifyEAT(token, tt.teeNonce, tt.vTpmNonce)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errorMessage != "" {
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Helper functions

func createValidClaims() jwt.MapClaims {
	return jwt.MapClaims{
		"iss": "https://test-issuer.com",
		"aud": "test-audience",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
		"nbf": time.Now().Add(-1 * time.Hour).Unix(),
		"x-ms-isolation-tee": map[string]any{
			"x-ms-sevsnpvm-familyId":          "1234567890abcdef",
			"x-ms-sevsnpvm-imageId":           "fedcba0987654321",
			"x-ms-sevsnpvm-launchmeasurement": "abcdef1234567890",
			"x-ms-sevsnpvm-bootloader-svn":    float64(1),
			"x-ms-sevsnpvm-tee-svn":           float64(2),
			"x-ms-sevsnpvm-snpfw-svn":         float64(3),
			"x-ms-sevsnpvm-microcode-svn":     float64(4),
			"x-ms-sevsnpvm-guestsvn":          float64(5),
			"x-ms-sevsnpvm-idkeydigest":       "1234567890abcdef",
			"x-ms-sevsnpvm-reportid":          "fedcba0987654321",
		},
	}
}

func signToken(claims jwt.MapClaims, key *rsa.PrivateKey, jku string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = testKID
	if jku != "" {
		token.Header["jku"] = jku
	}
	return token.SignedString(key)
}

func generateJWKS(pubKey *rsa.PublicKey, cert *x509.Certificate) *jose.JSONWebKeySet {
	key := jose.JSONWebKey{
		Key:          pubKey,
		KeyID:        testKID,
		Algorithm:    "RS256",
		Use:          "sig",
		Certificates: []*x509.Certificate{cert},
	}
	return &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{key},
	}
}
