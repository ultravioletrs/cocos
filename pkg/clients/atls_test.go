// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package clients

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

func TestLoadBasicTLSConfig(t *testing.T) {
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
			result, err := LoadBasicTLSConfig(tt.serverCAFile, tt.clientCert, tt.clientKey)

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
		name        string
		config      AttestedClientConfig
		expectedSec Security
		expectError bool
		errorMsg    string
	}{
		{
			name: "ValidATLSConfig",
			config: AttestedClientConfig{
				BaseConfig: BaseConfig{
					ServerCAFile: "",
				},
				AttestationPolicy: policyFile,
				ProductName:       "test-product",
			},
			expectedSec: WithATLS,
			expectError: false,
		},
		{
			name: "ValidMATLSConfig",
			config: AttestedClientConfig{
				BaseConfig: BaseConfig{
					ServerCAFile: caFile,
				},
				AttestationPolicy: policyFile,
				ProductName:       "test-product",
			},
			expectedSec: WithMATLS,
			expectError: false,
		},
		{
			name: "ValidATLSWithClientCert",
			config: AttestedClientConfig{
				BaseConfig: BaseConfig{
					ClientCert: certFile,
					ClientKey:  keyFile,
				},
				AttestationPolicy: policyFile,
				ProductName:       "test-product",
			},
			expectedSec: WithATLS,
			expectError: false,
		},
		{
			name: "NonexistentPolicyFile",
			config: AttestedClientConfig{
				AttestationPolicy: filepath.Join(tmpDir, "nonexistent.json"),
				ProductName:       "test-product",
			},
			expectedSec: WithoutTLS,
			expectError: true,
			errorMsg:    "failed to stat attestation policy file",
		},
		{
			name: "PolicyFileIsDirectory",
			config: AttestedClientConfig{
				AttestationPolicy: tmpDir, // Directory instead of file
				ProductName:       "test-product",
			},
			expectedSec: WithoutTLS,
			expectError: true,
			errorMsg:    "attestation policy file is not a regular file",
		},
		{
			name: "InvalidCAFile",
			config: AttestedClientConfig{
				BaseConfig: BaseConfig{
					ServerCAFile: filepath.Join(tmpDir, "nonexistent.crt"),
				},
				AttestationPolicy: policyFile,
				ProductName:       "test-product",
			},
			expectedSec: WithoutTLS,
			expectError: true,
			errorMsg:    "failed to read certificate file",
		},
		{
			name: "InvalidClientCert",
			config: AttestedClientConfig{
				BaseConfig: BaseConfig{
					ClientCert: filepath.Join(tmpDir, "nonexistent.crt"),
					ClientKey:  keyFile,
				},
				AttestationPolicy: policyFile,
				ProductName:       "test-product",
			},
			expectedSec: WithoutTLS,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := LoadATLSConfig(tt.config)

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

func TestVerifyCertificateSignature(t *testing.T) {
	// Generate test certificates
	cert, rootCert := generateCertificateChain(t)

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(rootCert)

	tests := []struct {
		name        string
		cert        *x509.Certificate
		rootCAs     *x509.CertPool
		expectError bool
	}{
		{
			name:        "ValidCertificateWithRootCA",
			cert:        cert,
			rootCAs:     rootCAs,
			expectError: false,
		},
		{
			name:        "SelfSignedCertificate",
			cert:        rootCert,
			rootCAs:     nil, // Will create self-signed verification
			expectError: false,
		},
		{
			name:        "InvalidCertificateWithRootCA",
			cert:        rootCert,           // Using root cert with different root CAs
			rootCAs:     x509.NewCertPool(), // Empty pool
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyCertificateSignature(tt.cert, tt.rootCAs)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVerifyPeerCertificateATLS(t *testing.T) {
	// Generate test certificate
	cert, rootCert := generateCertificateChain(t)

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(rootCert)

	// Create valid raw certificate data
	rawCerts := [][]byte{cert.Raw}
	nonce := make([]byte, 64)
	_, err := rand.Read(nonce)
	require.NoError(t, err)

	tests := []struct {
		name        string
		rawCerts    [][]byte
		nonce       []byte
		rootCAs     *x509.CertPool
		expectError bool
		errorMsg    string
	}{
		{
			name:        "InvalidCertificateData",
			rawCerts:    [][]byte{[]byte("invalid cert data")},
			nonce:       nonce,
			rootCAs:     rootCAs,
			expectError: true,
			errorMsg:    "failed to parse x509 certificate",
		},
		{
			name:        "ValidCertificateNoAttestationExtension",
			rawCerts:    rawCerts,
			nonce:       nonce,
			rootCAs:     rootCAs,
			expectError: true,
			errorMsg:    "attestation extension not found in certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyPeerCertificateATLS(tt.rawCerts, nil, tt.nonce, tt.rootCAs)

			assert.Error(t, err) // All test cases expect errors
			if tt.errorMsg != "" {
				assert.Contains(t, err.Error(), tt.errorMsg)
			}
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

func generateCertificateChain(t *testing.T) (cert, rootCert *x509.Certificate) {
	// Generate root certificate
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rootTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Root CA"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootCertDER, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)

	rootCert, err = x509.ParseCertificate(rootCertDER)
	require.NoError(t, err)

	// Generate leaf certificate signed by root
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	leafTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Leaf"},
			Country:      []string{"US"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, &rootTemplate, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)

	cert, err = x509.ParseCertificate(leafCertDER)
	require.NoError(t, err)

	return cert, rootCert
}
