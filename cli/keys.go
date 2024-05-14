// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"

	"github.com/spf13/cobra"
)

const (
	keyBitSize     = 4096
	privateKeyType = "RSA PRIVATE KEY"
	publicKeyType  = "PUBLIC KEY"
)

func (cli *CLI) NewKeysCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keys",
		Short: "Generate a new public/private key pair",
		Run: func(cmd *cobra.Command, args []string) {
			privKey, err := rsa.GenerateKey(rand.Reader, keyBitSize)
			if err != nil {
				log.Fatalf("Error generating public key: %v", err)
			}

			pubKey, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
			if err != nil {
				log.Fatalf("Error marshalling public key: %v", err)
			}

			privFile, err := os.Create("private.pem")
			if err != nil {
				log.Fatalf("Error creating private key file: %v", err)
			}
			defer privFile.Close()

			if err := pem.Encode(privFile, &pem.Block{
				Type:  privateKeyType,
				Bytes: x509.MarshalPKCS1PrivateKey(privKey),
			}); err != nil {
				log.Fatalf("Error encoding private key: %v", err)
			}

			pubFile, err := os.Create("public.pem")
			if err != nil {
				log.Fatalf("Error creating public key file: %v", err)
			}
			defer pubFile.Close()

			if err := pem.Encode(pubFile, &pem.Block{
				Type:  publicKeyType,
				Bytes: pubKey,
			}); err != nil {
				log.Fatalf("Error encoding public key: %v", err)
			}

			log.Println("Successfully generated public/private key pair")
		},
	}
}
