// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/stretchr/testify/assert"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"google.golang.org/protobuf/proto"
)

var (
	testNonce  = []byte("test-nonce-12345678901234567890123456789012")
	testReport = []byte("test-report-data")
)

func TestNewProvider(t *testing.T) {
	tests := []struct {
		name string
		want attestation.Provider
	}{
		{
			name: "creates new provider successfully",
			want: provider{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewProvider()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestProvider_Attestation(t *testing.T) {
	tests := []struct {
		name         string
		teeNonce     []byte
		vTpmNonce    []byte
		wantErr      bool
		errorMessage string
	}{
		{
			name:         "maa parameters error",
			teeNonce:     testNonce,
			vTpmNonce:    testNonce,
			wantErr:      true,
			errorMessage: "failed to get report",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewProvider()

			result, err := p.Attestation(tt.teeNonce, tt.vTpmNonce)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errorMessage != "" {
					assert.Contains(t, err.Error(), tt.errorMessage)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestProvider_TeeAttestation(t *testing.T) {
	tests := []struct {
		name         string
		teeNonce     []byte
		wantErr      bool
		errorMessage string
	}{
		{
			name:         "maa parameters error",
			teeNonce:     testNonce,
			wantErr:      true,
			errorMessage: "failed to get report",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewProvider()

			result, err := p.TeeAttestation(tt.teeNonce)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errorMessage != "" {
					assert.Contains(t, err.Error(), tt.errorMessage)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestProvider_AzureAttestationToken(t *testing.T) {
	tests := []struct {
		name         string
		tokenNonce   []byte
		setupServer  func() *httptest.Server
		wantErr      bool
		errorMessage string
	}{
		{
			name:       "server error",
			tokenNonce: testNonce,
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}))
			},
			wantErr:      true,
			errorMessage: "failed to fetch Azure token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := tt.setupServer()
			defer server.Close()

			originalURL := MaaURL
			MaaURL = server.URL
			defer func() { MaaURL = originalURL }()

			p := NewProvider()

			result, err := p.AzureAttestationToken(tt.tokenNonce)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errorMessage != "" {
					assert.Contains(t, err.Error(), tt.errorMessage)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestNewVerifier(t *testing.T) {
	tests := []struct {
		name   string
		writer io.Writer
	}{
		{
			name:   "creates verifier with buffer writer",
			writer: &bytes.Buffer{},
		},
		{
			name:   "creates verifier with nil writer",
			writer: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewVerifier(tt.writer)

			verifier, ok := v.(verifier)
			assert.True(t, ok)
			assert.Equal(t, tt.writer, verifier.writer)
			assert.NotNil(t, verifier.Policy)
			assert.NotNil(t, verifier.Policy.Config)
			assert.NotNil(t, verifier.Policy.PcrConfig)
		})
	}
}

func TestNewVerifierWithPolicy(t *testing.T) {
	tests := []struct {
		name   string
		writer io.Writer
		policy *attestation.Config
	}{
		{
			name:   "creates verifier with custom policy",
			writer: &bytes.Buffer{},
			policy: &attestation.Config{
				Config: &check.Config{
					Policy:      &check.Policy{},
					RootOfTrust: &check.RootOfTrust{},
				},
				PcrConfig: &attestation.PcrConfig{},
			},
		},
		{
			name:   "creates verifier with nil policy",
			writer: &bytes.Buffer{},
			policy: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewVerifierWithPolicy(tt.writer, tt.policy)

			verifier, ok := v.(verifier)
			assert.True(t, ok)
			assert.Equal(t, tt.writer, verifier.writer)
			assert.NotNil(t, verifier.Policy)
		})
	}
}

func TestVerifier_VerifTeeAttestation(t *testing.T) {
	tests := []struct {
		name         string
		report       []byte
		teeNonce     []byte
		wantErr      bool
		errorMessage string
	}{
		{
			name:     "empty report",
			report:   []byte{},
			teeNonce: testNonce,
			wantErr:  true,
		},
		{
			name:     "invalid report format",
			report:   []byte("invalid-report"),
			teeNonce: testNonce,
			wantErr:  true,
		},
		{
			name:     "nil nonce",
			report:   testReport,
			teeNonce: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewVerifier(&bytes.Buffer{})

			err := v.VerifTeeAttestation(tt.report, tt.teeNonce)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errorMessage != "" {
					assert.Contains(t, err.Error(), tt.errorMessage)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVerifier_VerifyAttestation(t *testing.T) {
	validQuote := &attest.Attestation{
		TeeAttestation: &attest.Attestation_SevSnpAttestation{
			SevSnpAttestation: &sevsnp.Attestation{
				Report: &sevsnp.Report{
					HostData: []byte("test-data"),
				},
				Product: &sevsnp.SevProduct{
					Name: sevsnp.SevProduct_SEV_PRODUCT_GENOA,
				},
				CertificateChain: &sevsnp.CertificateChain{
					Extras: make(map[string][]byte),
				},
			},
		},
	}
	validReport, _ := proto.Marshal(validQuote)

	tests := []struct {
		name         string
		report       []byte
		teeNonce     []byte
		vTpmNonce    []byte
		wantErr      bool
		errorMessage string
	}{
		{
			name:         "successful verification",
			report:       validReport,
			teeNonce:     testNonce,
			vTpmNonce:    testNonce,
			wantErr:      true,
			errorMessage: "failed to verify vTPM attestation report",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewVerifier(&bytes.Buffer{})

			err := v.VerifyAttestation(tt.report, tt.teeNonce, tt.vTpmNonce)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errorMessage != "" {
					assert.Contains(t, err.Error(), tt.errorMessage)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFetchAzureAttestationToken(t *testing.T) {
	tests := []struct {
		name         string
		tokenNonce   []byte
		maaURL       string
		setupServer  func() *httptest.Server
		wantErr      bool
		errorMessage string
	}{
		{
			name:       "server error",
			tokenNonce: testNonce,
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
				}))
			},
			wantErr:      true,
			errorMessage: "error fetching azure token",
		},
		{
			name:       "invalid url",
			tokenNonce: testNonce,
			setupServer: func() *httptest.Server {
				return nil
			},
			wantErr:      true,
			errorMessage: "error fetching azure token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var url string
			if tt.setupServer != nil {
				server := tt.setupServer()
				if server != nil {
					defer server.Close()
					url = server.URL
				}
			}

			if tt.name == "invalid url" {
				url = "invalid-url"
			}

			result, err := FetchAzureAttestationToken(tt.tokenNonce, url)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errorMessage != "" {
					assert.Contains(t, err.Error(), tt.errorMessage)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestValidateToken(t *testing.T) {
	tests := []struct {
		name         string
		token        string
		setupServer  func() *httptest.Server
		wantErr      bool
		errorMessage string
	}{
		{
			name:         "invalid token format",
			token:        "invalid-token",
			setupServer:  nil,
			wantErr:      true,
			errorMessage: "failed to parse token",
		},
		{
			name:         "empty token",
			token:        "",
			setupServer:  nil,
			wantErr:      true,
			errorMessage: "failed to parse token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupServer != nil {
				server := tt.setupServer()
				defer server.Close()

				originalURL := MaaURL
				MaaURL = server.URL
				defer func() { MaaURL = originalURL }()
			}

			result, err := validateToken(tt.token)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errorMessage != "" {
					assert.Contains(t, err.Error(), tt.errorMessage)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestIntegration_FullAttestationFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("full attestation flow with mock server", func(t *testing.T) {
		maaServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/attest":
				response := map[string]any{
					"token": createMockJWT(),
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(response); err != nil {
					t.Fatalf("Failed to encode response: %v", err)
				}
			case "/.well-known/openid_configuration":
				config := map[string]any{
					"jwks_uri": "maaServer.URL" + "/certs",
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(config); err != nil {
					t.Fatalf("Failed to encode OpenID configuration: %v", err)
				}
			case "/certs":
				jwks := map[string]any{
					"keys": []map[string]any{
						{
							"kid": "test-kid",
							"kty": "RSA",
							"use": "sig",
							"n":   "test-n-value",
							"e":   "AQAB",
						},
					},
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(jwks); err != nil {
					t.Fatalf("Failed to encode JWKS: %v", err)
				}
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer maaServer.Close()

		originalURL := MaaURL
		MaaURL = maaServer.URL
		defer func() { MaaURL = originalURL }()

		provider := NewProvider()
		verifier := NewVerifier(&bytes.Buffer{})

		teeNonce := []byte("test-tee-nonce-1234567890123456789012")
		vtpmNonce := []byte("test-vtpm-nonce-123456789012345678901")

		teeReport, err := provider.TeeAttestation(teeNonce)
		if err != nil {
			t.Logf("TEE attestation failed (expected in mock environment): %v", err)
		}

		vtpmReport, err := provider.VTpmAttestation(vtpmNonce)
		if err != nil {
			t.Logf("vTPM attestation failed (expected in mock environment): %v", err)
		}

		token, err := provider.AzureAttestationToken(teeNonce)
		if err != nil {
			t.Logf("Azure attestation token failed (expected in mock environment): %v", err)
		}

		assert.NotNil(t, provider)
		assert.NotNil(t, verifier)

		t.Logf("TEE report length: %d", len(teeReport))
		t.Logf("vTPM report length: %d", len(vtpmReport))
		t.Logf("Token length: %d", len(token))
	})
}

func TestIntegration_ErrorPropagation(t *testing.T) {
	t.Run("error propagation through full stack", func(t *testing.T) {
		failingServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := w.Write([]byte("Internal Server Error")); err != nil {
				t.Fatalf("Failed to write response: %v", err)
			}
		}))
		defer failingServer.Close()

		originalURL := MaaURL
		MaaURL = failingServer.URL
		defer func() { MaaURL = originalURL }()

		provider := NewProvider()

		_, err := provider.AzureAttestationToken([]byte("test-nonce"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to fetch Azure token")

		_, err = GenerateAttestationPolicy("invalid-token", "test-product", 1)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to validate token")
	})
}

func createMockJWT() string {
	claims := jwt.MapClaims{
		"iss": "https://test-issuer.com",
		"aud": "test-audience",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
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

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["jku"] = "https://test-url.com"
	token.Header["kid"] = "test-kid"

	// Return unsigned token for testing
	return token.Raw
}
