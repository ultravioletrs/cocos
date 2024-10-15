// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNewClient(t *testing.T) {
	caCertFile, clientCertFile, clientKeyFile, err := createCertificatesFiles()
	require.NoError(t, err)

	t.Cleanup(func() {
		os.Remove(caCertFile)
		os.Remove(clientCertFile)
		os.Remove(clientKeyFile)
	})

	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "Success without TLS",
			cfg: Config{
				URL: "localhost:7001",
			},
			wantErr: false,
		},
		{
			name: "Success with TLS",
			cfg: Config{
				URL:          "localhost:7001",
				ServerCAFile: caCertFile,
			},
			wantErr: false,
		},
		{
			name: "Success with mTLS",
			cfg: Config{
				URL:          "localhost:7001",
				ServerCAFile: caCertFile,
				ClientCert:   clientCertFile,
				ClientKey:    clientKeyFile,
			},
			wantErr: false,
		},
		{
			name: "Fail with invalid ServerCAFile",
			cfg: Config{
				URL:          "localhost:7001",
				ServerCAFile: "nonexistent.pem",
			},
			wantErr: true,
		},
		{
			name: "Fail with invalid ClientCert",
			cfg: Config{
				URL:          "localhost:7001",
				ServerCAFile: caCertFile,
				ClientCert:   "nonexistent.pem",
				ClientKey:    clientKeyFile,
			},
			wantErr: true,
		},
		{
			name: "Fail with invalid ClientKey",
			cfg: Config{
				URL:          "localhost:7001",
				ServerCAFile: caCertFile,
				ClientCert:   clientCertFile,
				ClientKey:    "nonexistent.pem",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.NoError(t, client.Close())
			}
		})
	}
}

func TestClientSecure(t *testing.T) {
	tests := []struct {
		name     string
		secure   security
		expected string
	}{
		{
			name:     "Without TLS",
			secure:   withoutTLS,
			expected: "without TLS",
		},
		{
			name:     "With TLS",
			secure:   withTLS,
			expected: "with TLS",
		},
		{
			name:     "With mTLS",
			secure:   withmTLS,
			expected: "with mTLS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &client{secure: tt.secure}
			assert.Equal(t, tt.expected, c.Secure())
		})
	}
}

func TestReadBackendInfo(t *testing.T) {
	validJSON := `{"snp_policy":{"report_data":"AAAA"},"root_of_trust":{"product_line":"Milan"}}`
	invalidJSON := `{"invalid_json"`

	tests := []struct {
		name         string
		manifestPath string
		fileContent  string
		wantErr      bool
	}{
		{
			name:         "Valid manifest",
			manifestPath: "valid_manifest.json",
			fileContent:  validJSON,
			wantErr:      false,
		},
		{
			name:         "Invalid JSON",
			manifestPath: "invalid_manifest.json",
			fileContent:  invalidJSON,
			wantErr:      true,
		},
		{
			name:         "Non-existent file",
			manifestPath: "nonexistent.json",
			fileContent:  "",
			wantErr:      true,
		},
		{
			name:         "Empty manifest path",
			manifestPath: "",
			fileContent:  "",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.manifestPath != "" && tt.fileContent != "" {
				err := os.WriteFile(tt.manifestPath, []byte(tt.fileContent), 0644)
				require.NoError(t, err)
				defer os.Remove(tt.manifestPath)
			}

			config := &AttestationConfiguration{}
			err := ReadBackendInfo(tt.manifestPath, config)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, config.SNPPolicy)
				assert.NotNil(t, config.RootOfTrust)
			}
		})
	}
}

func createCertificatesFiles() (string, string, string, error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", err
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", err
	}

	caCertFile, err := createTempFile(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER}))
	if err != nil {
		return "", "", "", err
	}

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", err
	}

	clientTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, &clientTemplate, &caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", err
	}

	clientCertFile, err := createTempFile(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER}))
	if err != nil {
		return "", "", "", err
	}

	clientKeyFile, err := createTempFile(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)}))
	if err != nil {
		return "", "", "", err
	}

	return caCertFile, clientCertFile, clientKeyFile, nil
}

func createTempFile(data []byte) (string, error) {
	file, err := createTempFileHandle()
	if err != nil {
		return "", err
	}

	_, err = file.Write(data)
	if err != nil {
		return "", err
	}

	err = file.Close()
	if err != nil {
		return "", err
	}

	return file.Name(), nil
}

func createTempFileHandle() (*os.File, error) {
	return os.CreateTemp("", "test")
}

func TestVerifyAttestationReportTLS(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	file, err := os.ReadFile("../../../attestation.bin")
	require.NoError(t, err)

	ar, err := abi.ReportCertsToProto(file)
	require.NoError(t, err)
	arBytes, err := proto.Marshal(ar)
	require.NoError(t, err)
	template.ExtraExtensions = []pkix.Extension{
		{
			Id:    customSEVSNPExtensionOID,
			Value: append(arBytes, make([]byte, attestationReportSize-len(arBytes))...),
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	backendinfoFile, err := os.ReadFile("../../../scripts/backend_info/backend_info.json")
	require.NoError(t, err)

	attestationConfiguration = AttestationConfiguration{
		SNPPolicy:   &check.Policy{},
		RootOfTrust: &check.RootOfTrust{},
	}
	err = json.Unmarshal(backendinfoFile, &attestationConfiguration)
	require.NoError(t, err)

	// Test cases
	tests := []struct {
		name      string
		rawCerts  [][]byte
		wantError bool
	}{
		{
			name:      "Valid certificate with attestation, malformed guest policy",
			rawCerts:  [][]byte{certDER},
			wantError: true,
		},
		{
			name:      "Invalid certificate",
			rawCerts:  [][]byte{[]byte("invalid cert")},
			wantError: true,
		},
		{
			name:      "Certificate without custom extension",
			rawCerts:  [][]byte{createCertWithoutCustomExtension(t)},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyAttestationReportTLS(tt.rawCerts, nil)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCheckIfCertificateSelfSigned(t *testing.T) {
	selfSignedCert := createSelfSignedCert(t)

	tests := []struct {
		name      string
		cert      *x509.Certificate
		wantError bool
	}{
		{
			name:      "Self-signed certificate",
			cert:      selfSignedCert,
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkIfCertificateSelfSigned(tt.cert)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFillInAttestationLocal(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test_home")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	cocosDir := tempDir + "/.cocos/Milan"
	err = os.MkdirAll(cocosDir, 0755)
	require.NoError(t, err)

	bundleContent := []byte("mock ASK ARK bundle")
	err = os.WriteFile(cocosDir+"/ask_ark.pem", bundleContent, 0644)
	require.NoError(t, err)

	attestationConfiguration = AttestationConfiguration{
		RootOfTrust: &check.RootOfTrust{},
		SNPPolicy:   &check.Policy{},
	}

	tests := []struct {
		name        string
		attestation *sevsnp.Attestation
		wantError   bool
	}{
		{
			name: "Empty attestation",
			attestation: &sevsnp.Attestation{
				CertificateChain: &sevsnp.CertificateChain{},
			},
			wantError: false,
		},
		{
			name: "Attestation with existing chain",
			attestation: &sevsnp.Attestation{
				CertificateChain: &sevsnp.CertificateChain{
					AskCert: []byte("existing ASK cert"),
					ArkCert: []byte("existing ARK cert"),
				},
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := fillInAttestationLocal(tt.attestation)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func createCertWithoutCustomExtension(t *testing.T) []byte {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	return certDER
}

func createSelfSignedCert(t *testing.T) *x509.Certificate {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}
