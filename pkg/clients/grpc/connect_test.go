// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
