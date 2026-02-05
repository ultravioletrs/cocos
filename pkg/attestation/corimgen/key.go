// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package corimgen

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

// LoadSigningKey loads a private key from a PEM-encoded file.
// It supports EC private keys (SEC 1) and PKCS#8 encoded keys.
func LoadSigningKey(path string) (crypto.Signer, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try parsing as EC private key
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try parsing as PKCS8
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if signer, ok := key.(crypto.Signer); ok {
			return signer, nil
		}
		return nil, fmt.Errorf("key is not a signer")
	}

	return nil, fmt.Errorf("failed to parse private key: must be EC or PKCS#8")
}
