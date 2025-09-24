// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build !embed
// +build !embed

package quoteprovider

import (
	"os"
	"path"
	"testing"

	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFillInAttestationLocal(t *testing.T) {
	originalHome := os.Getenv("HOME")
	defer func() {
		os.Setenv("HOME", originalHome)
	}()

	tempDir, err := os.MkdirTemp("", "test_home")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	os.Setenv("HOME", tempDir)

	cocosDir := path.Join(tempDir, cocosDirectory, sevSnpProductMilan)
	err = os.MkdirAll(cocosDir, 0o755)
	require.NoError(t, err)

	bundleContent := []byte("mock ASK ARK bundle")
	bundlePath := path.Join(cocosDir, arkAskBundleName)
	err = os.WriteFile(bundlePath, bundleContent, 0o644)
	require.NoError(t, err)

	config := &check.Config{
		RootOfTrust: &check.RootOfTrust{
			ProductLine: sevSnpProductMilan,
		},
		Policy: &check.Policy{},
	}

	tests := []struct {
		name          string
		attestation   *sevsnp.Attestation
		setupFunc     func()
		expectedError bool
		errorContains string
	}{
		{
			name: "Empty attestation - creates new chain",
			attestation: &sevsnp.Attestation{
				CertificateChain: nil,
			},
			setupFunc:     func() {},
			expectedError: true,
			errorContains: "could not find ASK or ASVK PEM block; could not find ARK PEM block",
		},
		{
			name: "Attestation with existing chain - no changes needed",
			attestation: &sevsnp.Attestation{
				CertificateChain: &sevsnp.CertificateChain{
					AskCert: []byte("existing ASK cert"),
					ArkCert: []byte("existing ARK cert"),
				},
			},
			setupFunc:     func() {},
			expectedError: false,
		},
		{
			name: "Attestation with empty chain - tries to load from file",
			attestation: &sevsnp.Attestation{
				CertificateChain: &sevsnp.CertificateChain{},
			},
			setupFunc:     func() {},
			expectedError: true,
			errorContains: "could not find ASK or ASVK PEM block; could not find ARK PEM block",
		},
		{
			name: "No bundle file exists - no error",
			attestation: &sevsnp.Attestation{
				CertificateChain: &sevsnp.CertificateChain{},
			},
			setupFunc: func() {
				os.Remove(bundlePath)
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("HOME", tempDir)
			if _, err := os.Stat(bundlePath); os.IsNotExist(err) {
				if err := os.WriteFile(bundlePath, bundleContent, 0o644); err != nil {
					t.Fatalf("Failed to write bundle file: %v", err)
				}
			}

			tt.setupFunc()

			err := fillInAttestationLocal(tt.attestation, config)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetProductName(t *testing.T) {
	tests := []struct {
		name     string
		product  string
		expected sevsnp.SevProduct_SevProductName
	}{
		{
			name:     "Milan product",
			product:  sevSnpProductMilan,
			expected: sevsnp.SevProduct_SEV_PRODUCT_MILAN,
		},
		{
			name:     "Genoa product",
			product:  sevSnpProductGenoa,
			expected: sevsnp.SevProduct_SEV_PRODUCT_GENOA,
		},
		{
			name:     "Unknown product",
			product:  "UnknownProduct",
			expected: sevsnp.SevProduct_SEV_PRODUCT_UNKNOWN,
		},
		{
			name:     "Empty product",
			product:  "",
			expected: sevsnp.SevProduct_SEV_PRODUCT_UNKNOWN,
		},
		{
			name:     "Case sensitive - milan lowercase",
			product:  "milan",
			expected: sevsnp.SevProduct_SEV_PRODUCT_UNKNOWN,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetProductName(tt.product)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestVerifyReport(t *testing.T) {
	tests := []struct {
		name          string
		attestation   *sevsnp.Attestation
		config        *check.Config
		expectedError bool
		errorContains string
	}{
		{
			name: "Invalid product line",
			attestation: &sevsnp.Attestation{
				CertificateChain: &sevsnp.CertificateChain{},
			},
			config: &check.Config{
				RootOfTrust: &check.RootOfTrust{
					ProductLine: "InvalidProduct",
				},
				Policy: &check.Policy{},
			},
			expectedError: true,
			errorContains: "product name must be",
		},
		{
			name: "Valid Milan product line",
			attestation: &sevsnp.Attestation{
				CertificateChain: &sevsnp.CertificateChain{
					AskCert: []byte("mock ask cert"),
					ArkCert: []byte("mock ark cert"),
				},
			},
			config: &check.Config{
				RootOfTrust: &check.RootOfTrust{
					ProductLine: sevSnpProductMilan,
				},
				Policy: &check.Policy{},
			},
			expectedError: true,
			errorContains: "attestation verification failed",
		},
		{
			name: "Valid Genoa product line",
			attestation: &sevsnp.Attestation{
				CertificateChain: &sevsnp.CertificateChain{
					AskCert: []byte("mock ask cert"),
					ArkCert: []byte("mock ark cert"),
				},
			},
			config: &check.Config{
				RootOfTrust: &check.RootOfTrust{
					ProductLine: sevSnpProductGenoa,
				},
				Policy: &check.Policy{},
			},
			expectedError: true,
			errorContains: "attestation verification failed",
		},
		{
			name: "Config with existing product policy",
			attestation: &sevsnp.Attestation{
				CertificateChain: &sevsnp.CertificateChain{
					AskCert: []byte("mock ask cert"),
					ArkCert: []byte("mock ark cert"),
				},
			},
			config: &check.Config{
				RootOfTrust: &check.RootOfTrust{
					ProductLine: sevSnpProductMilan,
				},
				Policy: &check.Policy{
					Product: &sevsnp.SevProduct{
						Name: sevsnp.SevProduct_SEV_PRODUCT_MILAN,
					},
				},
			},
			expectedError: true,
			errorContains: "attestation verification failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyReport(tt.attestation, tt.config)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateReport(t *testing.T) {
	tests := []struct {
		name          string
		attestation   *sevsnp.Attestation
		config        *check.Config
		expectedError bool
		errorContains string
	}{
		{
			name: "Basic validation test",
			attestation: &sevsnp.Attestation{
				CertificateChain: &sevsnp.CertificateChain{},
			},
			config: &check.Config{
				Policy: &check.Policy{
					Policy: 196608,
				},
			},
			expectedError: true,
			errorContains: "attestation validation failed",
		},
		{
			name: "Validation with report data",
			attestation: &sevsnp.Attestation{
				CertificateChain: &sevsnp.CertificateChain{},
			},
			config: &check.Config{
				Policy: &check.Policy{
					Policy:     196608,
					ReportData: []byte("test report datatest report datatest report datatest report data"),
				},
			},
			expectedError: true,
			errorContains: "attestation validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateReport(tt.attestation, tt.config)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFetchAttestation(t *testing.T) {
	tests := []struct {
		name          string
		reportData    []byte
		vmpl          uint
		expectedError bool
		errorContains string
	}{
		{
			name:          "Report data too large",
			reportData:    make([]byte, Nonce+1),
			vmpl:          0,
			expectedError: true,
			errorContains: "could not get quote provider",
		},
		{
			name:          "Valid report data size",
			reportData:    make([]byte, 32),
			vmpl:          0,
			expectedError: true,
			errorContains: "could not get quote provider",
		},
		{
			name:          "Maximum valid report data size",
			reportData:    make([]byte, Nonce),
			vmpl:          1,
			expectedError: true,
			errorContains: "could not get quote provider",
		},
		{
			name:          "Empty report data",
			reportData:    []byte{},
			vmpl:          0,
			expectedError: true,
			errorContains: "could not get quote provider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := FetchAttestation(tt.reportData, tt.vmpl)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Empty(t, result)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, result)
			}
		})
	}
}

func TestGetLeveledQuoteProvider(t *testing.T) {
	t.Run("GetLeveledQuoteProvider call", func(t *testing.T) {
		provider, err := GetLeveledQuoteProvider()

		if err != nil {
			assert.Error(t, err)
			assert.Nil(t, provider)
		} else {
			assert.NoError(t, err)
			assert.NotNil(t, provider)
		}
	})
}
