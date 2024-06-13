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
	"log"
	"os"
	"reflect"

	"github.com/spf13/cobra"
)

const (
	keyBitSize     = 4096
	privateKeyType = "RSA PRIVATE KEY"
	publicKeyType  = "PUBLIC KEY"
	publicKeyFile  = "public.pem"
	privateKeyFile = "private.pem"
)

func (cli *CLI) NewKeysCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keys <algorithm>",
		Short: "Generate a new public/private key pair",
		Long: "Generates a new public/private key pair using an algorithm of the users choice.\n" +
			"Supported algorithms are RSA, ecdsa, and ed25519.",
		Example: "./build/cocos-cli keys rsa",
		Args:    cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			switch args[0] {
			case "ecdsa":
				privEcdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					log.Fatalf("Error generating keys: %v", err)
				}

				pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privEcdsaKey.PublicKey)
				if err != nil {
					log.Fatalf("Error marshalling public key: %v", err)
				}

				generateAndWriteKeys(privEcdsaKey, pubKeyBytes)

			case "ed25519":
				pubEd25519Key, privEd25519Key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					log.Fatalf("Error generating keys: %v", err)
				}

				generateAndWriteKeys(privEd25519Key, pubEd25519Key)

			default:
				privKey, err := rsa.GenerateKey(rand.Reader, keyBitSize)
				if err != nil {
					log.Fatalf("Error generating keys: %v", err)
				}

				pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
				if err != nil {
					log.Fatalf("Error marshalling public key: %v", err)
				}

				generateAndWriteKeys(privKey, pubKeyBytes)
			}
		},
	}
}

func generateAndWriteKeys(privKey interface{}, pubKeyBytes []byte) {
	privFile, err := os.Create(privateKeyFile)
	if err != nil {
		log.Fatalf("Error creating private key file: %v", err)
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
		log.Fatalf("Error marshalling private key: %v", err)
	}

	if err := pem.Encode(privFile, &pem.Block{
		Type:  privateKeyType,
		Bytes: b,
	}); err != nil {
		log.Fatalf("Error encoding private key: %v", err)
	}

	pubFile, err := os.Create(publicKeyFile)
	if err != nil {
		log.Fatalf("Error creating public key file: %v", err)
	}
	defer pubFile.Close()

	if err := pem.Encode(pubFile, &pem.Block{
		Type:  publicKeyType,
		Bytes: pubKeyBytes,
	}); err != nil {
		log.Fatalf("Error encoding public key: %v", err)
	}

	log.Printf("Successfully generated public/private key pair of type: %s", reflect.TypeOf(privKey).String())
}
