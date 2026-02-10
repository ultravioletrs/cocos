// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package atls

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/azure"
	"github.com/ultravioletrs/cocos/pkg/attestation/eat"
	"github.com/ultravioletrs/cocos/pkg/attestation/tdx"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"golang.org/x/crypto/sha3"
)

type CertificateVerifier interface {
	VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate, nonce []byte) error
}

// CertificateVerifier handles certificate verification operations.
type certificateVerifier struct {
	rootCAs          *x509.CertPool
	verifierProvider func(attestation.PlatformType) (attestation.Verifier, error)
}

func NewCertificateVerifier(rootCAs *x509.CertPool) CertificateVerifier {
	return &certificateVerifier{
		rootCAs:          rootCAs,
		verifierProvider: platformVerifier,
	}
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
		if platformType, err := platformTypeFromOID(ext.Id); err == nil {
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
	// Decode EAT token from certificate extension
	// Note: We don't have the public key for verification here, so we decode without verification
	// The signature was created by the attester, and we trust the TEE hardware verification
	claims, err := eat.DecodeCBOR(extension, nil)
	if err != nil {
		return fmt.Errorf("failed to decode EAT token: %w", err)
	}

	// Verify nonce matches
	teeNonce := append(pubKey, nonce...)
	hashNonce := sha3.Sum512(teeNonce)

	// Compare nonces (EAT nonce should match our computed nonce)
	if len(claims.Nonce) != len(hashNonce) {
		return fmt.Errorf("nonce length mismatch: expected %d, got %d", len(hashNonce), len(claims.Nonce))
	}

	nonceMatch := true
	for i := range claims.Nonce {
		if claims.Nonce[i] != hashNonce[i] {
			nonceMatch = false
			break
		}
	}

	if !nonceMatch {
		return fmt.Errorf("nonce mismatch in EAT token")
	}

	// Get platform verifier
	verifier, err := v.verifierProvider(platformType)
	if err != nil {
		return fmt.Errorf("failed to get platform verifier: %w", err)
	}

	// Verify the binary attestation report embedded in EAT token
	if err = verifier.VerifyAttestation(claims.RawReport, hashNonce[:], hashNonce[:32]); err != nil {
		return fmt.Errorf("failed to verify attestation: %w", err)
	}

	return nil
}

func platformTypeFromOID(oid asn1.ObjectIdentifier) (attestation.PlatformType, error) {
	switch {
	case oid.Equal(SNPvTPMOID):
		return attestation.SNPvTPM, nil
	case oid.Equal(AzureOID):
		return attestation.Azure, nil
	case oid.Equal(TDXOID):
		return attestation.TDX, nil
	default:
		return 0, fmt.Errorf("unsupported OID: %v", oid)
	}
}

func platformVerifier(platformType attestation.PlatformType) (attestation.Verifier, error) {
	var verifier attestation.Verifier

	switch platformType {
	case attestation.SNPvTPM:
		verifier = vtpm.NewVerifier(nil)
	case attestation.Azure:
		verifier = azure.NewVerifier(nil)
	case attestation.TDX:
		verifier = tdx.NewVerifier()
	default:
		return nil, fmt.Errorf("unsupported platform type: %d", platformType)
	}

	err := verifier.JSONToPolicy(attestation.AttestationPolicyPath)
	if err != nil {
		return nil, err
	}
	return verifier, nil
}
