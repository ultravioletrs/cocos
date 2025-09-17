// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

// Helper function to generate a test certificate and key.
func generateTestCert() (certPEM, keyPEM []byte, err error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Org"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test City"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: nil,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode certificate
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	})

	return certPEM, keyPEM, nil
}

// Helper function to create temporary files for testing.
func createTempFile(t *testing.T, content []byte) string {
	tmpFile, err := os.CreateTemp("", "test-cert-*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer tmpFile.Close()

	if _, err := tmpFile.Write(content); err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	return tmpFile.Name()
}

func TestLoadCertFile(t *testing.T) {
	certPEM, _, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	tests := []struct {
		name     string
		certFile string
		wantErr  bool
		setup    func() string
		cleanup  func(string)
	}{
		{
			name:     "empty cert file path",
			certFile: "",
			wantErr:  false,
		},
		{
			name:    "valid cert file",
			wantErr: false,
			setup: func() string {
				return createTempFile(t, certPEM)
			},
			cleanup: func(path string) {
				os.Remove(path)
			},
		},
		{
			name:     "non-existent file",
			certFile: "/non/existent/file.pem",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			certFile := tt.certFile
			if tt.setup != nil {
				certFile = tt.setup()
			}
			if tt.cleanup != nil {
				defer tt.cleanup(certFile)
			}

			data, err := LoadCertFile(certFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadCertFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.certFile != "" && !tt.wantErr && len(data) == 0 {
				t.Errorf("LoadCertFile() with valid file should return data, got empty")
			}
		})
	}
}

func TestReadFileOrData(t *testing.T) {
	testData := "test certificate data"
	tempFile := createTempFile(t, []byte(testData))
	defer os.Remove(tempFile)

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "file path",
			input:   tempFile,
			want:    testData,
			wantErr: false,
		},
		{
			name:    "raw data with newlines",
			input:   "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
			want:    "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
			wantErr: false,
		},
		{
			name:    "short raw data without newlines",
			input:   "short data",
			want:    "short data",
			wantErr: true,
		},
		{
			name:    "non-existent file path",
			input:   "/non/existent/file.pem",
			want:    "",
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   "",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ReadFileOrData(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadFileOrData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && string(got) != tt.want {
				t.Errorf("ReadFileOrData() = %v, want %v", string(got), tt.want)
			}
		})
	}
}

func TestLoadX509KeyPair(t *testing.T) {
	certPEM, keyPEM, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	certFile := createTempFile(t, certPEM)
	keyFile := createTempFile(t, keyPEM)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	tests := []struct {
		name     string
		certfile string
		keyfile  string
		wantErr  bool
	}{
		{
			name:     "valid cert and key files",
			certfile: certFile,
			keyfile:  keyFile,
			wantErr:  false,
		},
		{
			name:     "valid cert and key data",
			certfile: string(certPEM),
			keyfile:  string(keyPEM),
			wantErr:  false,
		},
		{
			name:     "non-existent cert file",
			certfile: "/non/existent/cert.pem",
			keyfile:  keyFile,
			wantErr:  true,
		},
		{
			name:     "non-existent key file",
			certfile: certFile,
			keyfile:  "/non/existent/key.pem",
			wantErr:  true,
		},
		{
			name:     "invalid cert data",
			certfile: "invalid cert data",
			keyfile:  string(keyPEM),
			wantErr:  true,
		},
		{
			name:     "invalid key data",
			certfile: string(certPEM),
			keyfile:  "invalid key data",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := LoadX509KeyPair(tt.certfile, tt.keyfile)
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadX509KeyPair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && len(cert.Certificate) == 0 {
				t.Errorf("LoadX509KeyPair() returned empty certificate")
			}
		})
	}
}

func TestConfigureRootCA(t *testing.T) {
	certPEM, _, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	caFile := createTempFile(t, certPEM)
	defer os.Remove(caFile)

	tests := []struct {
		name         string
		tlsConfig    *tls.Config
		serverCAFile string
		wantErr      bool
		expectCA     bool
	}{
		{
			name:         "valid CA file",
			tlsConfig:    &tls.Config{},
			serverCAFile: caFile,
			wantErr:      false,
			expectCA:     true,
		},
		{
			name:         "valid CA data",
			tlsConfig:    &tls.Config{},
			serverCAFile: string(certPEM),
			wantErr:      false,
			expectCA:     true,
		},
		{
			name:         "empty CA file",
			tlsConfig:    &tls.Config{},
			serverCAFile: "",
			wantErr:      false,
			expectCA:     false,
		},
		{
			name:         "non-existent CA file",
			tlsConfig:    &tls.Config{},
			serverCAFile: "/non/existent/ca.pem",
			wantErr:      true,
			expectCA:     false,
		},
		{
			name:         "invalid CA data",
			tlsConfig:    &tls.Config{},
			serverCAFile: "invalid ca data",
			wantErr:      true,
			expectCA:     false,
		},
		{
			name:         "existing RootCAs pool",
			tlsConfig:    &tls.Config{RootCAs: x509.NewCertPool()},
			serverCAFile: caFile,
			wantErr:      false,
			expectCA:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ConfigureRootCA(tt.tlsConfig, tt.serverCAFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConfigureRootCA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.expectCA && tt.tlsConfig.RootCAs == nil {
				t.Errorf("ConfigureRootCA() should have created RootCAs pool")
			}

			if !tt.expectCA && tt.tlsConfig.RootCAs != nil && tt.serverCAFile == "" {
				t.Errorf("ConfigureRootCA() should not have created RootCAs pool for empty file")
			}
		})
	}
}

func TestConfigureClientCA(t *testing.T) {
	certPEM, _, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	caFile := createTempFile(t, certPEM)
	defer os.Remove(caFile)

	tests := []struct {
		name           string
		tlsConfig      *tls.Config
		clientCAFile   string
		wantConfigured bool
		wantErr        bool
	}{
		{
			name:           "valid client CA file",
			tlsConfig:      &tls.Config{},
			clientCAFile:   caFile,
			wantConfigured: true,
			wantErr:        false,
		},
		{
			name:           "valid client CA data",
			tlsConfig:      &tls.Config{},
			clientCAFile:   string(certPEM),
			wantConfigured: true,
			wantErr:        false,
		},
		{
			name:           "empty client CA file",
			tlsConfig:      &tls.Config{},
			clientCAFile:   "",
			wantConfigured: false,
			wantErr:        false,
		},
		{
			name:           "non-existent client CA file",
			tlsConfig:      &tls.Config{},
			clientCAFile:   "/non/existent/ca.pem",
			wantConfigured: false,
			wantErr:        true,
		},
		{
			name:           "invalid client CA data",
			tlsConfig:      &tls.Config{},
			clientCAFile:   "invalid ca data",
			wantConfigured: false,
			wantErr:        true,
		},
		{
			name:           "existing ClientCAs pool",
			tlsConfig:      &tls.Config{ClientCAs: x509.NewCertPool()},
			clientCAFile:   caFile,
			wantConfigured: true,
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configured, err := ConfigureClientCA(tt.tlsConfig, tt.clientCAFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConfigureClientCA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if configured != tt.wantConfigured {
				t.Errorf("ConfigureClientCA() configured = %v, want %v", configured, tt.wantConfigured)
			}

			if tt.wantConfigured && tt.tlsConfig.ClientCAs == nil {
				t.Errorf("ConfigureClientCA() should have created ClientCAs pool")
			}
		})
	}
}

func TestConfigureCertificateAuthorities(t *testing.T) {
	certPEM, _, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	caFile := createTempFile(t, certPEM)
	defer os.Remove(caFile)

	tests := []struct {
		name         string
		tlsConfig    *tls.Config
		serverCAFile string
		clientCAFile string
		wantMTLS     bool
		wantErr      bool
	}{
		{
			name:         "both server and client CA",
			tlsConfig:    &tls.Config{},
			serverCAFile: caFile,
			clientCAFile: caFile,
			wantMTLS:     true,
			wantErr:      false,
		},
		{
			name:         "only server CA",
			tlsConfig:    &tls.Config{},
			serverCAFile: caFile,
			clientCAFile: "",
			wantMTLS:     false,
			wantErr:      false,
		},
		{
			name:         "only client CA",
			tlsConfig:    &tls.Config{},
			serverCAFile: "",
			clientCAFile: caFile,
			wantMTLS:     true,
			wantErr:      false,
		},
		{
			name:         "no CAs",
			tlsConfig:    &tls.Config{},
			serverCAFile: "",
			clientCAFile: "",
			wantMTLS:     false,
			wantErr:      false,
		},
		{
			name:         "invalid server CA",
			tlsConfig:    &tls.Config{},
			serverCAFile: "/non/existent/server-ca.pem",
			clientCAFile: caFile,
			wantMTLS:     false,
			wantErr:      true,
		},
		{
			name:         "invalid client CA",
			tlsConfig:    &tls.Config{},
			serverCAFile: caFile,
			clientCAFile: "/non/existent/client-ca.pem",
			wantMTLS:     false,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mtls, err := ConfigureCertificateAuthorities(tt.tlsConfig, tt.serverCAFile, tt.clientCAFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConfigureCertificateAuthorities() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if mtls != tt.wantMTLS {
				t.Errorf("ConfigureCertificateAuthorities() mtls = %v, want %v", mtls, tt.wantMTLS)
			}
		})
	}
}

func TestSetupRegularTLS(t *testing.T) {
	certPEM, keyPEM, err := generateTestCert()
	if err != nil {
		t.Fatalf("Failed to generate test cert: %v", err)
	}

	certFile := createTempFile(t, certPEM)
	keyFile := createTempFile(t, keyPEM)
	caFile := createTempFile(t, certPEM)
	defer func() {
		os.Remove(certFile)
		os.Remove(keyFile)
		os.Remove(caFile)
	}()

	tests := []struct {
		name         string
		certFile     string
		keyFile      string
		serverCAFile string
		clientCAFile string
		wantMTLS     bool
		wantErr      bool
		expectedAuth tls.ClientAuthType
	}{
		{
			name:         "regular TLS without mTLS",
			certFile:     certFile,
			keyFile:      keyFile,
			serverCAFile: "",
			clientCAFile: "",
			wantMTLS:     false,
			wantErr:      false,
			expectedAuth: tls.NoClientCert,
		},
		{
			name:         "TLS with mTLS",
			certFile:     certFile,
			keyFile:      keyFile,
			serverCAFile: caFile,
			clientCAFile: caFile,
			wantMTLS:     true,
			wantErr:      false,
			expectedAuth: tls.RequireAndVerifyClientCert,
		},
		{
			name:         "TLS with only server CA",
			certFile:     certFile,
			keyFile:      keyFile,
			serverCAFile: caFile,
			clientCAFile: "",
			wantMTLS:     false,
			wantErr:      false,
			expectedAuth: tls.NoClientCert,
		},
		{
			name:         "invalid certificate file",
			certFile:     "/non/existent/cert.pem",
			keyFile:      keyFile,
			serverCAFile: "",
			clientCAFile: "",
			wantMTLS:     false,
			wantErr:      true,
			expectedAuth: tls.NoClientCert,
		},
		{
			name:         "invalid key file",
			certFile:     certFile,
			keyFile:      "/non/existent/key.pem",
			serverCAFile: "",
			clientCAFile: "",
			wantMTLS:     false,
			wantErr:      true,
			expectedAuth: tls.NoClientCert,
		},
		{
			name:         "invalid server CA file",
			certFile:     certFile,
			keyFile:      keyFile,
			serverCAFile: "/non/existent/server-ca.pem",
			clientCAFile: "",
			wantMTLS:     false,
			wantErr:      true,
			expectedAuth: tls.NoClientCert,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SetupRegularTLS(tt.certFile, tt.keyFile, tt.serverCAFile, tt.clientCAFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetupRegularTLS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if result == nil {
				t.Errorf("SetupRegularTLS() returned nil result")
				return
			}

			if result.MTLS != tt.wantMTLS {
				t.Errorf("SetupRegularTLS() MTLS = %v, want %v", result.MTLS, tt.wantMTLS)
			}

			if result.Config.ClientAuth != tt.expectedAuth {
				t.Errorf("SetupRegularTLS() ClientAuth = %v, want %v", result.Config.ClientAuth, tt.expectedAuth)
			}

			if len(result.Config.Certificates) == 0 {
				t.Errorf("SetupRegularTLS() should have at least one certificate")
			}
		})
	}
}

func TestBuildMTLSDescription(t *testing.T) {
	tests := []struct {
		name         string
		serverCAFile string
		clientCAFile string
		want         string
	}{
		{
			name:         "both server and client CA files",
			serverCAFile: "/path/to/server-ca.pem",
			clientCAFile: "/path/to/client-ca.pem",
			want:         "root ca /path/to/server-ca.pem client ca /path/to/client-ca.pem",
		},
		{
			name:         "only server CA file",
			serverCAFile: "/path/to/server-ca.pem",
			clientCAFile: "",
			want:         "root ca /path/to/server-ca.pem",
		},
		{
			name:         "only client CA file",
			serverCAFile: "",
			clientCAFile: "/path/to/client-ca.pem",
			want:         "client ca /path/to/client-ca.pem",
		},
		{
			name:         "no CA files",
			serverCAFile: "",
			clientCAFile: "",
			want:         "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildMTLSDescription(tt.serverCAFile, tt.clientCAFile)
			if got != tt.want {
				t.Errorf("BuildMTLSDescription() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestErrorConstants(t *testing.T) {
	// Test that error constants are properly defined
	if ErrAppendServerCA == nil {
		t.Error("ErrAppendServerCA should not be nil")
	}

	if ErrAppendClientCA == nil {
		t.Error("ErrAppendClientCA should not be nil")
	}

	if ErrAppendServerCA.Error() != "failed to append server ca to tls.Config" {
		t.Errorf("ErrAppendServerCA message = %v, want 'failed to append server ca to tls.Config'", ErrAppendServerCA.Error())
	}

	if ErrAppendClientCA.Error() != "failed to append client ca to tls.Config" {
		t.Errorf("ErrAppendClientCA message = %v, want 'failed to append client ca to tls.Config'", ErrAppendClientCA.Error())
	}
}

func TestTLSSetupResult(t *testing.T) {
	// Test that TLSSetupResult struct works as expected
	config := &tls.Config{}
	result := &TLSSetupResult{
		Config: config,
		MTLS:   true,
	}

	if result.Config != config {
		t.Error("TLSSetupResult Config field should match assigned value")
	}

	if !result.MTLS {
		t.Error("TLSSetupResult MTLS field should be true")
	}
}

func TestReadFileOrDataEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "999 chars without newline (should try file)",
			input:   strings.Repeat("a", 999),
			wantErr: true, // Should fail as file doesn't exist
		},
		{
			name:    "1001 chars without newline (should treat as data)",
			input:   strings.Repeat("a", 1001),
			wantErr: false,
		},
		{
			name:    "short string with newline (should treat as data)",
			input:   "short\ndata",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ReadFileOrData(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ReadFileOrData() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
