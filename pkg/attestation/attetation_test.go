// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCCPlatform(t *testing.T) {
	tests := []struct {
		name                  string
		sevSnpGuestExists     bool
		sevSnpGuestvTPMExists bool
		tdxGuestExists        bool
		isAzure               bool
		expected              PlatformType
	}{
		{
			name:                  "No CC platform detected",
			sevSnpGuestExists:     false,
			sevSnpGuestvTPMExists: false,
			tdxGuestExists:        false,
			isAzure:               false,
			expected:              NoCC,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CCPlatform()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSevSnpGuestDeviceExists(t *testing.T) {
	tests := []struct {
		name          string
		openDeviceErr error
		expected      bool
	}{
		{
			name:          "device does not exist or fails to open",
			openDeviceErr: fmt.Errorf("device not found"),
			expected:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SevSnpGuestDeviceExists()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSevSnpGuestvTPMExists(t *testing.T) {
	tests := []struct {
		name         string
		vTPMExists   bool
		sevSnpExists bool
		expected     bool
	}{
		{
			name:         "vTPM exists but SEV-SNP does not",
			vTPMExists:   true,
			sevSnpExists: false,
			expected:     false,
		},
		{
			name:         "SEV-SNP exists but vTPM does not",
			vTPMExists:   false,
			sevSnpExists: true,
			expected:     false,
		},
		{
			name:         "neither exists",
			vTPMExists:   false,
			sevSnpExists: false,
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SevSnpGuestvTPMExists()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestVTPMExists(t *testing.T) {
	tests := []struct {
		name       string
		openTPMErr error
		expected   bool
	}{
		{
			name:       "TPM fails to open",
			openTPMErr: fmt.Errorf("TPM not found"),
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := vTPMExists()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsAzureVM(t *testing.T) {
	tests := []struct {
		name         string
		vTPMExists   bool
		statusCode   int
		responseBody string
		httpError    error
		expected     bool
	}{
		{
			name:         "Azure VM with empty response body",
			vTPMExists:   true,
			statusCode:   http.StatusOK,
			responseBody: "",
			httpError:    nil,
			expected:     false,
		},
		{
			name:         "Azure VM with non-200 status code",
			vTPMExists:   true,
			statusCode:   http.StatusNotFound,
			responseBody: "",
			httpError:    nil,
			expected:     false,
		},
		{
			name:         "HTTP request error",
			vTPMExists:   true,
			statusCode:   0,
			responseBody: "",
			httpError:    fmt.Errorf("connection failed"),
			expected:     false,
		},
		{
			name:         "vTPM does not exist",
			vTPMExists:   false,
			statusCode:   http.StatusOK,
			responseBody: `{"compute":{"name":"test-vm"}}`,
			httpError:    nil,
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "GET", r.Method)
				assert.Equal(t, "true", r.Header.Get("Metadata"))
				expectedURL := fmt.Sprintf("/?api-version=%s", azureApiVersion)
				assert.Equal(t, expectedURL, r.URL.String())

				if tt.httpError != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				w.WriteHeader(tt.statusCode)
				if tt.responseBody != "" {
					if _, err := w.Write([]byte(tt.responseBody)); err != nil {
						t.Fatalf("Failed to write response body: %v", err)
					}
				}
			}))
			defer server.Close()

			if tt.httpError != nil {
				server.Close()
			}

			result := isAzureVM()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestTDXGuestDeviceExists(t *testing.T) {
	tests := []struct {
		name          string
		openDeviceErr error
		expected      bool
	}{
		{
			name:          "TDX device does not exist or fails to open",
			openDeviceErr: fmt.Errorf("device not found"),
			expected:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TDXGuestDeviceExists()
			assert.Equal(t, tt.expected, result)
		})
	}
}
