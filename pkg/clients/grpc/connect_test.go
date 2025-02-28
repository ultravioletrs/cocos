// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	att "github.com/ultravioletrs/cocos/pkg/attestation"
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
		name     string
		cfg      BaseConfig
		agentCfg AgentClientConfig
		wantErr  bool
		err      error
	}{
		{
			name: "Success without TLS",
			cfg: BaseConfig{
				URL: "localhost:7001",
			},
			wantErr: false,
			err:     nil,
		},
		{
			name: "Success with TLS",
			cfg: BaseConfig{
				URL:          "localhost:7001",
				ServerCAFile: caCertFile,
			},
			wantErr: false,
			err:     nil,
		},
		{
			name: "Success with mTLS",
			cfg: BaseConfig{
				URL:          "localhost:7001",
				ServerCAFile: caCertFile,
				ClientCert:   clientCertFile,
				ClientKey:    clientKeyFile,
			},
			wantErr: false,
			err:     nil,
		},
		{
			name: "Success agent client with mTLS",
			agentCfg: AgentClientConfig{
				BaseConfig: BaseConfig{
					URL:          "localhost:7001",
					ServerCAFile: caCertFile,
					ClientCert:   clientCertFile,
					ClientKey:    clientKeyFile,
				},
			},
			wantErr: false,
			err:     nil,
		},
		{
			name: "Success agent client with aTLS",
			agentCfg: AgentClientConfig{
				BaseConfig: BaseConfig{
					URL:          "localhost:7001",
					ServerCAFile: caCertFile,
					ClientCert:   clientCertFile,
					ClientKey:    clientKeyFile,
				},
				AttestedTLS:       true,
				AttestationPolicy: "../../../scripts/attestation_policy/attestation_policy.json",
			},
			wantErr: false,
			err:     nil,
		},
		{
			name: "Failed agent client with aTLS",
			agentCfg: AgentClientConfig{
				BaseConfig: BaseConfig{
					URL:          "localhost:7001",
					ServerCAFile: caCertFile,
					ClientCert:   clientCertFile,
					ClientKey:    clientKeyFile,
				},
				AttestedTLS:       true,
				AttestationPolicy: "no such file",
			},
			wantErr: true,
			err:     fmt.Errorf("failed to read Attestation Policy"),
		},
		{
			name: "Fail with invalid ServerCAFile",
			cfg: BaseConfig{
				URL:          "localhost:7001",
				ServerCAFile: "nonexistent.pem",
			},
			wantErr: true,
			err:     errFailedToLoadRootCA,
		},
		{
			name: "Fail with invalid ClientCert",
			cfg: BaseConfig{
				URL:          "localhost:7001",
				ServerCAFile: caCertFile,
				ClientCert:   "nonexistent.pem",
				ClientKey:    clientKeyFile,
			},
			wantErr: true,
			err:     errFailedToLoadClientCertKey,
		},
		{
			name: "Fail with invalid ClientKey",
			cfg: BaseConfig{
				URL:          "localhost:7001",
				ServerCAFile: caCertFile,
				ClientCert:   clientCertFile,
				ClientKey:    "nonexistent.pem",
			},
			wantErr: true,
			err:     errFailedToLoadClientCertKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var client Client
			if strings.Contains(tt.name, "agent client") {
				client, err = NewClient(tt.agentCfg)
			} else {
				client, err = NewClient(tt.cfg)
			}
			assert.True(t, errors.Contains(err, tt.err), fmt.Sprintf("expected error %v, got %v", tt.err, err))
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
		{
			name:     "With aTLS",
			secure:   withaTLS,
			expected: WithATLS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &client{secure: tt.secure}
			assert.Equal(t, tt.expected, c.Secure())
		})
	}
}

func TestReadAttestationPolicy(t *testing.T) {
	validJSON := `{"pcr_values":{"sha256":{"0":"123"},"sha384":{"0":"123"}},"policy":{"report_data":"AAAA"},"root_of_trust":{"product_line":"Milan"}}`
	invalidJSON := `{"invalid_json"`
	invalidJSONPCR := `{"pcr_values":{"sha256":{"0":true},"sha384":{"0":"123"}},"policy":{"report_data":"AAAA"},"root_of_trust":{"product_line":"Milan"}}`

	cases := []struct {
		name         string
		manifestPath string
		fileContent  string
		err          error
	}{
		{
			name:         "Valid manifest",
			manifestPath: "valid_manifest.json",
			fileContent:  validJSON,
			err:          nil,
		},
		{
			name:         "Invalid JSON",
			manifestPath: "invalid_manifest.json",
			fileContent:  invalidJSON,
			err:          att.ErrAttestationPolicyDecode,
		},
		{
			name:         "Non-existent file",
			manifestPath: "nonexistent.json",
			fileContent:  "",
			err:          att.ErrAttestationPolicyOpen,
		},
		{
			name:         "Empty manifest path",
			manifestPath: "",
			fileContent:  "",
			err:          att.ErrAttestationPolicyMissing,
		},
		{
			name:         "Invalid JSON PCR",
			manifestPath: "invalid_manifest.json",
			fileContent:  invalidJSONPCR,
			err:          att.ErrAttestationPolicyDecode,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.manifestPath != "" && tt.fileContent != "" {
				err := os.WriteFile(tt.manifestPath, []byte(tt.fileContent), 0o644)
				require.NoError(t, err)
				defer os.Remove(tt.manifestPath)
			}

			config := att.Config{SnpCheck: &check.Config{}, PcrConfig: &att.PcrConfig{}}
			err := att.ReadAttestationPolicy(tt.manifestPath, &config)

			assert.True(t, errors.Contains(err, tt.err), fmt.Sprintf("expected error %v, got %v", tt.err, err))
			if tt.err == nil {
				assert.NotNil(t, config.SnpCheck.Policy)
				assert.NotNil(t, config.SnpCheck.RootOfTrust)
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

func TestCheckIfCertificateSelfSigned(t *testing.T) {
	selfSignedCert := createSelfSignedCert(t)

	tests := []struct {
		name string
		cert *x509.Certificate
		err  error
	}{
		{
			name: "Self-signed certificate",
			cert: selfSignedCert,
			err:  nil,
		},
		{
			name: "missing certificate contents",
			cert: &x509.Certificate{},
			err:  errors.New("x509: missing ASN.1 contents; use ParseCertificate"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkIfCertificateSelfSigned(tt.cert)
			assert.True(t, errors.Contains(err, tt.err), fmt.Sprintf("expected error %v, got %v", tt.err, err))
		})
	}
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
