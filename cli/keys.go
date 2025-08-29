// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"

	"github.com/spf13/cobra"
)

const (
	keyBitSize     = 4096
	rsaKeyType     = "PRIVATE KEY"
	ecdsaKeyType   = "EC PRIVATE KEY"
	ed25519KeyType = "PRIVATE KEY"
	publicKeyType  = "PUBLIC KEY"
	publicKeyFile  = "public.pem"
	privateKeyFile = "private.pem"
	ECDSA          = "ecdsa"
	ED25519        = "ed25519"
)

var KeyType string

func (cli *CLI) NewKeysCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keys",
		Short: "Generate a new public/private key pair",
		Long: "Generates a new public/private key pair using an algorithm of the users choice.\n" +
			"Supported algorithms are RSA, ecdsa, and ed25519.",
		Example: "./build/cocos-cli keys -k rsa",
		Args:    cobra.ExactArgs(0),
		Run: func(cmd *cobra.Command, args []string) {
			switch KeyType {
			case ECDSA:
				privEcdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					printError(cmd, "Error generating keys: %v ❌ ", err)
					return
				}

				pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privEcdsaKey.PublicKey)
				if err != nil {
					printError(cmd, "Error marshalling public key: %v ❌ ", err)
					return
				}

				if err := generateAndWriteKeys(privEcdsaKey, pubKeyBytes, ecdsaKeyType); err != nil {
					printError(cmd, "Error generating and writing keys: %v ❌ ", err)
					return
				}

			case ED25519:
				pubEd25519Key, privEd25519Key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					printError(cmd, "Error generating keys: %v ❌ ", err)
					return
				}
				pubKey, err := x509.MarshalPKIXPublicKey(pubEd25519Key)
				if err != nil {
					printError(cmd, "Error marshalling public key: %v ❌ ", err)
					return
				}
				if err := generateAndWriteKeys(privEd25519Key, pubKey, ed25519KeyType); err != nil {
					printError(cmd, "Error generating and writing keys: %v ❌ ", err)
					return
				}

			default:
				privKey, err := rsa.GenerateKey(rand.Reader, keyBitSize)
				if err != nil {
					printError(cmd, "Error generating keys: %v ❌ ", err)
					return
				}

				pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
				if err != nil {
					printError(cmd, "Error marshalling public key: %v ❌ ", err)
					return
				}
				if err := generateAndWriteKeys(privKey, pubKeyBytes, rsaKeyType); err != nil {
					printError(cmd, "Error generating and writing keys: %v ❌ ", err)
					return
				}
			}

			cmd.Printf("Successfully generated public/private key pair of type: %s", KeyType)
		},
	}
}

func generateAndWriteKeys(privKey any, pubKeyBytes []byte, keyType string) error {
	privFile, err := os.Create(privateKeyFile)
	if err != nil {
		return err
	}
	defer privFile.Close()

	var b []byte
	switch privKey := privKey.(type) {
	case *rsa.PrivateKey:
		b = x509.MarshalPKCS1PrivateKey(privKey)
	case *ecdsa.PrivateKey:
		b, err = x509.MarshalECPrivateKey(privKey)
	case ed25519.PrivateKey:
		b, err = x509.MarshalPKCS8PrivateKey(privKey)
	}
	if err != nil {
		return err
	}

	if err := pem.Encode(privFile, &pem.Block{
		Type:  keyType,
		Bytes: b,
	}); err != nil {
		return err
	}

	pubFile, err := os.Create(publicKeyFile)
	if err != nil {
		return err
	}
	defer pubFile.Close()

	if err := pem.Encode(pubFile, &pem.Block{
		Type:  publicKeyType,
		Bytes: pubKeyBytes,
	}); err != nil {
		return err
	}

	return nil
}
