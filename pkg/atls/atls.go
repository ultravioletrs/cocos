// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package atls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/azure"
	"github.com/ultravioletrs/cocos/pkg/attestation/tdx"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"golang.org/x/crypto/sha3"
)

const (
	vmpl2         = 2
	organization  = "Ultraviolet"
	country       = "Serbia"
	province      = ""
	locality      = "Belgrade"
	streetAddress = "Bulevar Arsenija Carnojevica 103"
	postalCode    = "11000"
	notAfterYear  = 1
	notAfterMonth = 0
	notAfterDay   = 0
)

var (
	SNPvTPMOID = asn1.ObjectIdentifier{2, 99999, 1, 0}
	AzureOID   = asn1.ObjectIdentifier{2, 99999, 1, 1}
	TDXOID     = asn1.ObjectIdentifier{2, 99999, 1, 2}
)

func getPlatformProvider(platformType attestation.PlatformType) (attestation.Provider, error) {
	switch platformType {
	case attestation.SNPvTPM:
		return vtpm.NewProvider(true, vmpl2), nil
	case attestation.Azure:
		return azure.NewProvider(), nil
	case attestation.TDX:
		return tdx.NewProvider(), nil
	default:
		return nil, fmt.Errorf("unsupported platform type: %d", platformType)
	}
}

func getPlatformVerifier(platformType attestation.PlatformType) (attestation.Verifier, error) {
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

func getOID(platformType attestation.PlatformType) (asn1.ObjectIdentifier, error) {
	switch platformType {
	case attestation.SNPvTPM:
		return SNPvTPMOID, nil
	case attestation.Azure:
		return AzureOID, nil
	case attestation.TDX:
		return TDXOID, nil
	default:
		return nil, fmt.Errorf("unsupported platform type: %d", platformType)
	}
}

func GetPlatformTypeFromOID(oid asn1.ObjectIdentifier) (attestation.PlatformType, error) {
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

func getCertificateExtension(pubKey []byte, nonce []byte) (pkix.Extension, error) {
	teeNonce := append(pubKey, nonce...)
	hashNonce := sha3.Sum512(teeNonce)

	pType := attestation.CCPlatform()

	provider, err := getPlatformProvider(pType)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to get platform provider: %w", err)
	}

	teeOid, err := getOID(pType)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to get OID for platform type %d: %w", pType, err)
	}

	rawAttestation, err := provider.Attestation(hashNonce[:], hashNonce[:vtpm.Nonce])
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to get attestation: %w", err)
	}

	return pkix.Extension{
		Id:    teeOid,
		Value: rawAttestation,
	}, nil
}

func VerifyCertificateExtension(extension []byte, pubKey []byte, nonce []byte, pType attestation.PlatformType) error {
	teeNonce := append(pubKey, nonce...)
	hashNonce := sha3.Sum512(teeNonce)

	verifier, err := getPlatformVerifier(pType)
	if err != nil {
		return fmt.Errorf("failed to get platform verifier: %w", err)
	}

	if err = verifier.VerifyAttestation(extension, hashNonce[:], hashNonce[:vtpm.Nonce]); err != nil {
		fmt.Printf("failed to verify attestation for platform type %d: %v\n", pType, err)
		return err
	}

	return nil
}

func GetATLSCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	curve := elliptic.P256()

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private/public key: %w", err)
	}

	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key to DER format: %w", err)
	}

	sniLength := len(clientHello.ServerName)
	if sniLength < 7 || clientHello.ServerName[sniLength-6:] != ".nonce" {
		return nil, fmt.Errorf("invalid server name: %s", clientHello.ServerName)
	}

	nonceStr := clientHello.ServerName[:sniLength-6]
	nonce, err := hex.DecodeString(nonceStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce from server name: %w", err)
	}

	if len(nonce) != 64 {
		return nil, fmt.Errorf("invalid nonce length: expected 64 bytes, got %d bytes", len(nonce))
	}

	attestExtension, err := getCertificateExtension(pubKeyDER, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate extension: %w", err)
	}

	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(202403311),
		Subject: pkix.Name{
			Organization:  []string{organization},
			Country:       []string{country},
			Province:      []string{province},
			Locality:      []string{locality},
			StreetAddress: []string{streetAddress},
			PostalCode:    []string{postalCode},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(notAfterYear, notAfterMonth, notAfterDay),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{attestExtension},
	}

	DERBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{DERBytes},
		PrivateKey:  privateKey,
	}, nil
}
