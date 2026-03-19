// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package corimgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadSigningKey(t *testing.T) {
	tempDir := t.TempDir()

	// 1. EC Private Key (SEC 1)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecBytes, err := x509.MarshalECPrivateKey(ecKey)
	require.NoError(t, err)
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecBytes})
	ecFile := filepath.Join(tempDir, "ec.pem")
	err = os.WriteFile(ecFile, ecPEM, 0o644)
	require.NoError(t, err)

	// 2. PKCS8 Private Key
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(ecKey)
	require.NoError(t, err)
	pkcs8PEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})
	pkcs8File := filepath.Join(tempDir, "pkcs8.pem")
	err = os.WriteFile(pkcs8File, pkcs8PEM, 0o644)
	require.NoError(t, err)

	// 3. Invalid PEM
	invalidPEMFile := filepath.Join(tempDir, "invalid.pem")
	err = os.WriteFile(invalidPEMFile, []byte("not a pem"), 0o644)
	require.NoError(t, err)

	// 4. Non-existent file
	noFile := filepath.Join(tempDir, "noexist.pem")

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name:    "Load EC key successfully",
			path:    ecFile,
			wantErr: false,
		},
		{
			name:    "Load PKCS8 key successfully",
			path:    pkcs8File,
			wantErr: false,
		},
		{
			name:    "Fail on invalid PEM",
			path:    invalidPEMFile,
			wantErr: true,
		},
		{
			name:    "Fail on non-existent file",
			path:    noFile,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := LoadSigningKey(tt.path)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, key)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, key)
			}
		})
	}
}
