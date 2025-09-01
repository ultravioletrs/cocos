// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

func TestNewKeysCmd(t *testing.T) {
	cli := &CLI{}
	cmd := cli.NewKeysCmd()

	if cmd.Use != "keys" {
		t.Errorf("Expected Use to be 'keys', got %s", cmd.Use)
	}

	if cmd.Short != "Generate a new public/private key pair" {
		t.Errorf("Unexpected Short description: %s", cmd.Short)
	}
}

func TestGenerateAndWriteKeys(t *testing.T) {
	tests := []struct {
		name    string
		keyType string
	}{
		{"RSA", "rsa"},
		{"ECDSA", "ecdsa"},
		{"ED25519", "ed25519"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			KeyType = tt.keyType
			cmd := (&CLI{}).NewKeysCmd()
			cmd.Run(cmd, []string{})

			if _, err := os.Stat(privateKeyFile); os.IsNotExist(err) {
				t.Errorf("Private key file was not created")
			}
			if _, err := os.Stat(publicKeyFile); os.IsNotExist(err) {
				t.Errorf("Public key file was not created")
			}

			privKeyData, err := os.ReadFile(privateKeyFile)
			if err != nil {
				t.Fatalf("Failed to read private key file: %v", err)
			}
			privPem, _ := pem.Decode(privKeyData)
			if privPem == nil {
				t.Fatalf("Failed to decode private key PEM")
			}

			var privKey any
			switch tt.keyType {
			case "rsa":
				privKey, err = x509.ParsePKCS1PrivateKey(privPem.Bytes)
			case "ecdsa":
				privKey, err = x509.ParseECPrivateKey(privPem.Bytes)
			case "ed25519":
				privKey, err = x509.ParsePKCS8PrivateKey(privPem.Bytes)
			}
			if err != nil {
				t.Fatalf("Failed to parse private key: %v", err)
			}

			switch tt.keyType {
			case "rsa":
				if _, ok := privKey.(*rsa.PrivateKey); !ok {
					t.Errorf("Expected RSA private key, got %T", privKey)
				}
			case "ecdsa":
				if _, ok := privKey.(*ecdsa.PrivateKey); !ok {
					t.Errorf("Expected ECDSA private key, got %T", privKey)
				}
			case "ed25519":
				if _, ok := privKey.(ed25519.PrivateKey); !ok {
					t.Errorf("Expected ED25519 private key, got %T", privKey)
				}
			}

			os.Remove(privateKeyFile)
			os.Remove(publicKeyFile)
		})
	}
}
