// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecurity_String(t *testing.T) {
	tests := []struct {
		name     string
		security Security
		expected string
	}{
		{
			name:     "WithoutTLS",
			security: WithoutTLS,
			expected: "without TLS",
		},
		{
			name:     "WithTLS",
			security: WithTLS,
			expected: "with TLS",
		},
		{
			name:     "WithMTLS",
			security: WithMTLS,
			expected: "with mTLS",
		},
		{
			name:     "WithATLS",
			security: WithATLS,
			expected: "with aTLS",
		},
		{
			name:     "WithMATLS",
			security: WithMATLS,
			expected: "with maTLS",
		},
		{
			name:     "InvalidSecurity",
			security: Security(999),
			expected: "without TLS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.security.String())
		})
	}
}

func TestLoadBasicConfig(t *testing.T) {
	// Create temporary directory for test files
	tmpDir := t.TempDir()

	// Generate test certificate and key
	cert, key, caPEM := generateTestCertificates(t)

	certFile := filepath.Join(tmpDir, "client.crt")
	keyFile := filepath.Join(tmpDir, "client.key")
	caFile := filepath.Join(tmpDir, "ca.crt")

	require.NoError(t, os.WriteFile(certFile, cert, 0o644))
	require.NoError(t, os.WriteFile(keyFile, key, 0o644))
	require.NoError(t, os.WriteFile(caFile, caPEM, 0o644))

	tests := []struct {
		name           string
		serverCAFile   string
		clientCert     string
		clientKey      string
		expectedSec    Security
		expectedConfig bool
		expectError    bool
	}{
		{
			name:           "NoTLS",
			serverCAFile:   "",
			clientCert:     "",
			clientKey:      "",
			expectedSec:    WithoutTLS,
			expectedConfig: false,
			expectError:    false,
		},
		{
			name:           "TLSOnly",
			serverCAFile:   caFile,
			clientCert:     "",
			clientKey:      "",
			expectedSec:    WithTLS,
			expectedConfig: true,
			expectError:    false,
		},
		{
			name:           "MTLS",
			serverCAFile:   caFile,
			clientCert:     certFile,
			clientKey:      keyFile,
			expectedSec:    WithMTLS,
			expectedConfig: true,
			expectError:    false,
		},
		{
			name:           "MTLSWithoutCA",
			serverCAFile:   "",
			clientCert:     certFile,
			clientKey:      keyFile,
			expectedSec:    WithMTLS,
			expectedConfig: true,
			expectError:    false,
		},
		{
			name:           "InvalidCAFile",
			serverCAFile:   filepath.Join(tmpDir, "nonexistent.crt"),
			clientCert:     "",
			clientKey:      "",
			expectedSec:    WithoutTLS,
			expectedConfig: false,
			expectError:    true,
		},
		{
			name:           "InvalidCertFile",
			serverCAFile:   "",
			clientCert:     filepath.Join(tmpDir, "nonexistent.crt"),
			clientKey:      keyFile,
			expectedSec:    WithoutTLS,
			expectedConfig: false,
			expectError:    true,
		},
		{
			name:           "InvalidKeyFile",
			serverCAFile:   "",
			clientCert:     certFile,
			clientKey:      filepath.Join(tmpDir, "nonexistent.key"),
			expectedSec:    WithoutTLS,
			expectedConfig: false,
			expectError:    true,
		},
		{
			name:           "MismatchedCertKey",
			serverCAFile:   "",
			clientCert:     caFile, // Using CA file as cert (wrong format)
			clientKey:      keyFile,
			expectedSec:    WithoutTLS,
			expectedConfig: false,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := LoadBasicConfig(tt.serverCAFile, tt.clientCert, tt.clientKey)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tt.expectedSec, result.Security)

			if tt.expectedConfig {
				assert.NotNil(t, result.Config)
			} else {
				assert.Nil(t, result.Config)
			}
		})
	}
}

func TestLoadATLSConfig(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	cert, key, caPEM := generateTestCertificates(t)

	certFile := filepath.Join(tmpDir, "client.crt")
	keyFile := filepath.Join(tmpDir, "client.key")
	caFile := filepath.Join(tmpDir, "ca.crt")
	policyFile := filepath.Join(tmpDir, "policy.json")

	require.NoError(t, os.WriteFile(certFile, cert, 0o644))
	require.NoError(t, os.WriteFile(keyFile, key, 0o644))
	require.NoError(t, os.WriteFile(caFile, caPEM, 0o644))
	require.NoError(t, os.WriteFile(policyFile, []byte(`{"policy": "test"}`), 0o644))

	tests := []struct {
		name              string
		attestationPolicy string
		serverCAFile      string
		clientCert        string
		clientKey         string
		expectedSec       Security
		expectError       bool
		errorMsg          string
	}{
		{
			name:              "ValidATLSConfig",
			attestationPolicy: policyFile,
			serverCAFile:      "",
			clientCert:        "",
			clientKey:         "",
			expectedSec:       WithATLS,
			expectError:       false,
		},
		{
			name:              "ValidMATLSConfig",
			attestationPolicy: policyFile,
			serverCAFile:      caFile,
			clientCert:        "",
			clientKey:         "",
			expectedSec:       WithMATLS,
			expectError:       false,
		},
		{
			name:              "ValidATLSWithClientCert",
			attestationPolicy: policyFile,
			serverCAFile:      "",
			clientCert:        certFile,
			clientKey:         keyFile,
			expectedSec:       WithATLS,
			expectError:       false,
		},
		{
			name:              "NonexistentPolicyFile",
			attestationPolicy: filepath.Join(tmpDir, "nonexistent.json"),
			serverCAFile:      "",
			clientCert:        "",
			clientKey:         "",
			expectedSec:       WithoutTLS,
			expectError:       true,
			errorMsg:          "failed to stat attestation policy file",
		},
		{
			name:              "PolicyFileIsDirectory",
			attestationPolicy: tmpDir, // Directory instead of file
			serverCAFile:      "",
			clientCert:        "",
			clientKey:         "",
			expectedSec:       WithoutTLS,
			expectError:       true,
			errorMsg:          "attestation policy file is not a regular file",
		},
		{
			name:              "InvalidCAFile",
			attestationPolicy: policyFile,
			serverCAFile:      filepath.Join(tmpDir, "nonexistent.crt"),
			clientCert:        "",
			clientKey:         "",
			expectedSec:       WithoutTLS,
			expectError:       true,
			errorMsg:          "failed to read certificate file",
		},
		{
			name:              "InvalidClientCert",
			attestationPolicy: policyFile,
			serverCAFile:      "",
			clientCert:        filepath.Join(tmpDir, "nonexistent.crt"),
			clientKey:         keyFile,
			expectedSec:       WithoutTLS,
			expectError:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := LoadATLSConfig(tt.attestationPolicy, tt.serverCAFile, tt.clientCert, tt.clientKey)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tt.expectedSec, result.Security)
			assert.NotNil(t, result.Config)

			// Verify TLS config properties
			assert.True(t, result.Config.InsecureSkipVerify)
			assert.NotNil(t, result.Config.VerifyPeerCertificate)
			assert.NotEmpty(t, result.Config.ServerName)
			assert.Contains(t, result.Config.ServerName, ".nonce")
		})
	}
}

func TestLoadRootCAs(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate test certificate
	_, _, caPEM := generateTestCertificates(t)

	validCAFile := filepath.Join(tmpDir, "valid_ca.crt")
	invalidCAFile := filepath.Join(tmpDir, "invalid_ca.crt")
	nonExistentFile := filepath.Join(tmpDir, "nonexistent.crt")

	require.NoError(t, os.WriteFile(validCAFile, caPEM, 0o644))
	require.NoError(t, os.WriteFile(invalidCAFile, []byte("invalid pem data"), 0o644))

	tests := []struct {
		name        string
		caFile      string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "ValidCAFile",
			caFile:      validCAFile,
			expectError: false,
		},
		{
			name:        "NonExistentFile",
			caFile:      nonExistentFile,
			expectError: true,
			errorMsg:    "failed to read certificate file",
		},
		{
			name:        "InvalidPEMData",
			caFile:      invalidCAFile,
			expectError: true,
			errorMsg:    "failed to decode PEM block",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rootCAs, err := loadRootCAs(tt.caFile)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, rootCAs)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, rootCAs)
		})
	}
}

// Helper functions for generating test certificates

func generateTestCertificates(t *testing.T) (certPEM, keyPEM, caPEM []byte) {
	// Generate CA certificate
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})

	// Generate client certificate
	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	clientTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Client"},
			Country:      []string{"US"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, &clientTemplate, &caTemplate, &clientKey.PublicKey, caKey)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientCertDER,
	})

	clientKeyDER, err := x509.MarshalPKCS8PrivateKey(clientKey)
	require.NoError(t, err)

	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: clientKeyDER,
	})

	return certPEM, keyPEM, caPEM
}
