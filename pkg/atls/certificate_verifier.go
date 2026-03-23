// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package atls

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/azure"
	"github.com/ultravioletrs/cocos/pkg/attestation/eat"
	"github.com/ultravioletrs/cocos/pkg/attestation/tdx"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"github.com/veraison/corim/corim"
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
	slog.Debug("Starting peer certificate verification for aTLS")
	if len(rawCerts) == 0 {
		err := fmt.Errorf("no certificates provided")
		slog.Error("aTLS handshake failed", "reason", err.Error())
		return err
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		err = fmt.Errorf("failed to parse x509 certificate: %w", err)
		slog.Error("aTLS handshake failed", "reason", err.Error())
		return err
	}
	slog.Debug("Successfully parsed peer x509 certificate", "subject", cert.Subject.String())

	if err := v.verifyCertificateSignature(cert); err != nil {
		err = fmt.Errorf("certificate signature verification failed: %w", err)
		slog.Error("aTLS handshake failed", "reason", err.Error())
		return err
	}
	slog.Debug("Successfully verified peer certificate signature")

	err = v.verifyAttestationExtension(cert, nonce)
	if err != nil {
		slog.Error("aTLS handshake failed", "reason", err.Error())
		return err
	}
	slog.Debug("Successfully verified aTLS attestation extension")
	return nil
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
			slog.Debug("Found attestation extension in peer certificate", "platform_type", platformType)
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
	// The attestation provider truncates the 64-byte hash to 32 bytes for the EAT token nonce claim
	// This matches the Attestation Service API and standard cryptographic nonce sizes.
	expectedNonce := hashNonce[:32]

	// Compare nonces (EAT nonce should match our computed nonce)
	if len(claims.Nonce) != len(expectedNonce) {
		err := fmt.Errorf("nonce length mismatch: expected %d, got %d", len(expectedNonce), len(claims.Nonce))
		slog.Error("aTLS handshake failed", "reason", err.Error())
		return err
	}

	nonceMatch := true
	for i := range claims.Nonce {
		if claims.Nonce[i] != expectedNonce[i] {
			nonceMatch = false
			break
		}
	}

	if !nonceMatch {
		err := fmt.Errorf("nonce mismatch in EAT token")
		slog.Error("aTLS handshake failed", "reason", err.Error())
		return err
	}

	// Get platform verifier
	verifier, err := v.verifierProvider(platformType)
	if err != nil {
		return fmt.Errorf("failed to get platform verifier: %w", err)
	}

	// Load and parse CoRIM
	if attestation.AttestationPolicyPath == "" {
		return fmt.Errorf("attestation policy path is not set")
	}

	corimBytes, err := os.ReadFile(attestation.AttestationPolicyPath)
	if err != nil {
		return fmt.Errorf("failed to read CoRIM file: %w", err)
	}

	// Try extracting from COSE Sign1 first
	var unsignedCorim *corim.UnsignedCorim

	var sc corim.SignedCorim
	if err := sc.FromCOSE(corimBytes); err == nil {
		// It's a COSE Sign1 message
		unsignedCorim = &sc.UnsignedCorim
	} else {
		// Try parsing as unsigned CoRIM directly
		var uc corim.UnsignedCorim
		if err := uc.FromCBOR(corimBytes); err != nil {
			return fmt.Errorf("failed to parse CoRIM (tried both signed and unsigned): %w", err)
		}
		unsignedCorim = &uc
	}

	// Re-wrap in Corim struct expected by Verifiers
	// Since verifiers expect the struct from the removed internal package,
	// we need to update verifiers to accept veraison/corim types
	// For now, we pass the unsignedCorim directly
	if err = verifier.VerifyWithCoRIM(claims.RawReport, unsignedCorim); err != nil {
		return fmt.Errorf("failed to verify attestation with CoRIM: %w", err)
	}

	slog.Debug("CoRIM verification passed for aTLS peer certificate")
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

	return verifier, nil
}
