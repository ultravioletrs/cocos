// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package kbs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	config := Config{
		URL:     "http://localhost:8080",
		Timeout: 10 * time.Second,
	}

	client := NewClient(config)
	assert.NotNil(t, client)
}

func TestAttest(t *testing.T) {
	tests := []struct {
		name           string
		evidence       []byte
		runtimeData    RuntimeData
		serverResponse AttestResponse
		serverStatus   int
		expectError    bool
	}{
		{
			name:     "successful attestation",
			evidence: []byte(`{"tdx-report": "base64_evidence"}`),
			runtimeData: RuntimeData{
				Nonce: "base64_nonce",
			},
			serverResponse: AttestResponse{
				Token: "jwt_token_here",
			},
			serverStatus: http.StatusOK,
			expectError:  false,
		},
		{
			name:     "attestation failure - unauthorized",
			evidence: []byte(`{"tdx-report": "invalid_evidence"}`),
			runtimeData: RuntimeData{
				Nonce: "base64_nonce",
			},
			serverStatus: http.StatusUnauthorized,
			expectError:  true,
		},
		{
			name:     "attestation failure - server error",
			evidence: []byte(`{"tdx-report": "base64_evidence"}`),
			runtimeData: RuntimeData{
				Nonce: "base64_nonce",
			},
			serverStatus: http.StatusInternalServerError,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/kbs/v0/attest", r.URL.Path)
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

				var req AttestRequest
				err := json.NewDecoder(r.Body).Decode(&req)
				require.NoError(t, err)

				assert.Equal(t, tt.runtimeData.Nonce, req.RuntimeData.Nonce)

				w.WriteHeader(tt.serverStatus)
				if tt.serverStatus == http.StatusOK {
					json.NewEncoder(w).Encode(tt.serverResponse)
				}
			}))
			defer server.Close()

			client := NewClient(Config{
				URL:     server.URL,
				Timeout: 5 * time.Second,
			})

			token, err := client.Attest(context.Background(), tt.evidence, tt.runtimeData)

			if tt.expectError {
				assert.Error(t, err)
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.serverResponse.Token, token)
			}
		})
	}
}

func TestGetResource(t *testing.T) {
	tests := []struct {
		name           string
		token          string
		resourcePath   string
		serverResponse []byte
		serverStatus   int
		expectError    bool
	}{
		{
			name:           "successful resource retrieval",
			token:          "valid_token",
			resourcePath:   "default/key/my-key",
			serverResponse: []byte("decryption_key_data"),
			serverStatus:   http.StatusOK,
			expectError:    false,
		},
		{
			name:         "resource not found",
			token:        "valid_token",
			resourcePath: "default/key/nonexistent",
			serverStatus: http.StatusNotFound,
			expectError:  true,
		},
		{
			name:         "unauthorized - invalid token",
			token:        "invalid_token",
			resourcePath: "default/key/my-key",
			serverStatus: http.StatusUnauthorized,
			expectError:  true,
		},
		{
			name:         "server error",
			token:        "valid_token",
			resourcePath: "default/key/my-key",
			serverStatus: http.StatusInternalServerError,
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectedPath := "/kbs/v0/resource/" + tt.resourcePath
				assert.Equal(t, expectedPath, r.URL.Path)
				assert.Equal(t, http.MethodGet, r.Method)
				assert.Equal(t, "Bearer "+tt.token, r.Header.Get("Authorization"))

				w.WriteHeader(tt.serverStatus)
				if tt.serverStatus == http.StatusOK {
					w.Write(tt.serverResponse)
				}
			}))
			defer server.Close()

			client := NewClient(Config{
				URL:     server.URL,
				Timeout: 5 * time.Second,
			})

			resource, err := client.GetResource(context.Background(), tt.token, tt.resourcePath)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resource)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.serverResponse, resource)
			}
		})
	}
}

func TestAttestWithContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(AttestResponse{Token: "token"})
	}))
	defer server.Close()

	client := NewClient(Config{
		URL:     server.URL,
		Timeout: 5 * time.Second,
	})

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := client.Attest(ctx, []byte("evidence"), RuntimeData{Nonce: "nonce"})
		assert.Error(t, err)
	})

	t.Run("context timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		_, err := client.Attest(ctx, []byte("evidence"), RuntimeData{Nonce: "nonce"})
		assert.Error(t, err)
	})
}

func TestGetResourceWithContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("resource_data"))
	}))
	defer server.Close()

	client := NewClient(Config{
		URL:     server.URL,
		Timeout: 5 * time.Second,
	})

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		_, err := client.GetResource(ctx, "token", "default/key/test")
		assert.Error(t, err)
	})

	t.Run("context timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		_, err := client.GetResource(ctx, "token", "default/key/test")
		assert.Error(t, err)
	})
}
