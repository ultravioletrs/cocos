// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package atls

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/ultravioletrs/cocos/pkg/attestation"
	"golang.org/x/crypto/sha3"
)

type CertificateVerifier interface {
	VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate, nonce []byte) error
}

// CertificateVerifier handles certificate verification operations.
type certificateVerifier struct {
	rootCAs *x509.CertPool
}

func NewCertificateVerifier(rootCAs *x509.CertPool) CertificateVerifier {
	return &certificateVerifier{rootCAs: rootCAs}
}

func (v *certificateVerifier) VerifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate, nonce []byte) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no certificates provided")
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse x509 certificate: %w", err)
	}

	if err := v.verifyCertificateSignature(cert); err != nil {
		return fmt.Errorf("certificate signature verification failed: %w", err)
	}

	return v.verifyAttestationExtension(cert, nonce)
}

func (v *certificateVerifier) verifyCertificateSignature(cert *x509.Certificate) error {
	rootCAs := v.rootCAs
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
		rootCAs.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Roots:       rootCAs,
		CurrentTime: time.Now(),
	}

	_, err := cert.Verify(opts)
	return err
}

func (v *certificateVerifier) verifyAttestationExtension(cert *x509.Certificate, nonce []byte) error {
	for _, ext := range cert.Extensions {
		if platformType, err := getPlatformTypeFromOID(ext.Id); err == nil {
			pubKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
			if err != nil {
				return fmt.Errorf("failed to marshal public key: %w", err)
			}
			return v.verifyCertificateExtension(ext.Value, pubKeyDER, nonce, platformType)
		}
	}
	return fmt.Errorf("attestation extension not found in certificate")
}

func (v *certificateVerifier) verifyCertificateExtension(extension []byte, pubKey []byte, nonce []byte, platformType attestation.PlatformType) error {
	verifier, err := getPlatformVerifier(platformType)
	if err != nil {
		return fmt.Errorf("failed to get platform verifier: %w", err)
	}

	teeNonce := append(pubKey, nonce...)
	hashNonce := sha3.Sum512(teeNonce)

	if err = verifier.VerifyAttestation(extension, hashNonce[:], hashNonce[:32]); err != nil {
		return fmt.Errorf("failed to verify attestation: %w", err)
	}

	return nil
}
