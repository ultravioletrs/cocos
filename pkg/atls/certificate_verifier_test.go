// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package atls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/eat"
	"golang.org/x/crypto/sha3"
)

type mockVerifier struct {
	verifyAttestationFunc func(report []byte, teeNonce []byte, vTpmNonce []byte) error
}

func (m *mockVerifier) VerifyAttestation(report []byte, teeNonce []byte, vTpmNonce []byte) error {
	if m.verifyAttestationFunc != nil {
		return m.verifyAttestationFunc(report, teeNonce, vTpmNonce)
	}
	return nil
}

func (m *mockVerifier) VerifTeeAttestation(report []byte, teeNonce []byte) error {
	return nil
}

func (m *mockVerifier) VerifVTpmAttestation(report []byte, vTpmNonce []byte) error {
	return nil
}

func (m *mockVerifier) VerifyEAT(eatToken []byte, teeNonce []byte, vTpmNonce []byte) error {
	return nil
}

func (m *mockVerifier) JSONToPolicy(path string) error {
	return nil
}

func TestVerifyPeerCertificate_Success(t *testing.T) {
	// Setup keys and cert templates
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(caCert)

	// Create verifier with mock platform verifier
	verifier := NewCertificateVerifier(rootCAs).(*certificateVerifier)
	verifier.verifierProvider = func(pt attestation.PlatformType) (attestation.Verifier, error) {
		return &mockVerifier{
			verifyAttestationFunc: func(report []byte, teeNonce []byte, vTpmNonce []byte) error {
				return nil
			},
		}, nil
	}

	peerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Prepare EAT Claims
	nonce := []byte("test-nonce")
	peerPubKeyDER, err := x509.MarshalPKIXPublicKey(&peerKey.PublicKey)
	require.NoError(t, err)

	teeNonce := append(peerPubKeyDER, nonce...)
	hashNonce := sha3.Sum512(teeNonce)

	claims := eat.EATClaims{
		Nonce:     hashNonce[:],
		RawReport: []byte("mock-report"),
	}
	eatBytes, err := cbor.Marshal(claims)
	require.NoError(t, err)

	// Create Peer Cert with EAT extension
	peerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Peer"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{
			{
				Id:    SNPvTPMOID, // Use SNPvTPMOID as default testing OID
				Value: eatBytes,
			},
		},
	}
	peerCertDER, err := x509.CreateCertificate(rand.Reader, peerTemplate, caCert, &peerKey.PublicKey, caKey)
	require.NoError(t, err)

	err = verifier.VerifyPeerCertificate([][]byte{peerCertDER}, nil, nonce)
	assert.NoError(t, err)
}

func TestVerifyPeerCertificate_Failures(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertDER, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caCertDER)
	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(caCert)

	verifier := NewCertificateVerifier(rootCAs).(*certificateVerifier)

	peerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	peerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, peerTemplate, caCert, &peerKey.PublicKey, caKey)

	err := verifier.VerifyPeerCertificate([][]byte{certDER}, nil, []byte("nonce"))
	assert.ErrorContains(t, err, "attestation extension not found")

	nonce := []byte("nonce1")
	wrongNonce := []byte("nonce2")
	peerPubKeyDER, _ := x509.MarshalPKIXPublicKey(&peerKey.PublicKey)
	teeNonce := append(peerPubKeyDER, wrongNonce...) // Mismatching input
	hashNonce := sha3.Sum512(teeNonce)

	claims := eat.EATClaims{Nonce: hashNonce[:], RawReport: []byte("rep")}
	eatBytes, _ := cbor.Marshal(claims)

	peerTemplate.ExtraExtensions = []pkix.Extension{{Id: SNPvTPMOID, Value: eatBytes}}
	certDERMismatch, _ := x509.CreateCertificate(rand.Reader, peerTemplate, caCert, &peerKey.PublicKey, caKey)

	err = verifier.VerifyPeerCertificate([][]byte{certDERMismatch}, nil, nonce) // Pass nonce1
	assert.ErrorContains(t, err, "nonce mismatch")
}

func TestVerifyPeerCertificate_Empty(t *testing.T) {
	verifier := NewCertificateVerifier(nil)
	err := verifier.VerifyPeerCertificate(nil, nil, nil)
	assert.ErrorContains(t, err, "no certificates provided")
}
