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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/eat"
	"github.com/veraison/corim/corim"
	"golang.org/x/crypto/sha3"
)

type mockVerifier struct {
	verifyWithCoRIMFunc func(report []byte, manifest *corim.UnsignedCorim) error
}

func (m *mockVerifier) VerifyWithCoRIM(report []byte, manifest *corim.UnsignedCorim) error {
	if m.verifyWithCoRIMFunc != nil {
		return m.verifyWithCoRIMFunc(report, manifest)
	}
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
			verifyWithCoRIMFunc: func(report []byte, manifest *corim.UnsignedCorim) error {
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

	// Create dummy CoRIM file
	tempDir, err := os.MkdirTemp("", "policy")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	c := corim.NewUnsignedCorim()
	c.SetID("cocos-test-id")
	corimBytes, err := c.ToCBOR()
	require.NoError(t, err)

	policyPath := filepath.Join(tempDir, "attestation_policy.json")
	err = os.WriteFile(policyPath, corimBytes, 0o644)
	require.NoError(t, err)

	oldPolicyPath := attestation.AttestationPolicyPath
	attestation.AttestationPolicyPath = policyPath
	t.Cleanup(func() {
		attestation.AttestationPolicyPath = oldPolicyPath
	})

	err = verifier.VerifyPeerCertificate([][]byte{peerCertDER}, nil, nonce)
	assert.NoError(t, err)
}

func TestVerifyPeerCertificate_AzureSuccess(t *testing.T) {
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
	verifier.verifierProvider = func(pt attestation.PlatformType) (attestation.Verifier, error) {
		return &mockVerifier{}, nil
	}

	peerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nonce := []byte("test-nonce")
	peerPubKeyDER, _ := x509.MarshalPKIXPublicKey(&peerKey.PublicKey)
	teeNonce := append(peerPubKeyDER, nonce...)
	hashNonce := sha3.Sum512(teeNonce)

	claims := eat.EATClaims{Nonce: hashNonce[:], RawReport: []byte("rep")}
	eatBytes, _ := cbor.Marshal(claims)

	peerTemplate := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "Azure Peer"},
		NotBefore:       time.Now().Add(-1 * time.Hour),
		NotAfter:        time.Now().Add(1 * time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: AzureOID, Value: eatBytes}},
	}
	peerCertDER, _ := x509.CreateCertificate(rand.Reader, peerTemplate, caCert, &peerKey.PublicKey, caKey)

	tempDir := t.TempDir()
	c := corim.NewUnsignedCorim()
	c.SetID("cocos-test-id")
	corimBytes, _ := c.ToCBOR()
	policyPath := filepath.Join(tempDir, "policy.cbor")
	_ = os.WriteFile(policyPath, corimBytes, 0o644)

	oldPolicyPath := attestation.AttestationPolicyPath
	attestation.AttestationPolicyPath = policyPath
	t.Cleanup(func() { attestation.AttestationPolicyPath = oldPolicyPath })

	err := verifier.VerifyPeerCertificate([][]byte{peerCertDER}, nil, nonce)
	assert.NoError(t, err)
}

func TestVerifyPeerCertificate_TDXSuccess(t *testing.T) {
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
	verifier.verifierProvider = func(pt attestation.PlatformType) (attestation.Verifier, error) {
		return &mockVerifier{}, nil
	}

	peerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	nonce := []byte("test-nonce")
	peerPubKeyDER, _ := x509.MarshalPKIXPublicKey(&peerKey.PublicKey)
	teeNonce := append(peerPubKeyDER, nonce...)
	hashNonce := sha3.Sum512(teeNonce)

	claims := eat.EATClaims{Nonce: hashNonce[:], RawReport: []byte("rep")}
	eatBytes, _ := cbor.Marshal(claims)

	peerTemplate := &x509.Certificate{
		SerialNumber:    big.NewInt(3),
		Subject:         pkix.Name{CommonName: "TDX Peer"},
		NotBefore:       time.Now().Add(-1 * time.Hour),
		NotAfter:        time.Now().Add(1 * time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: TDXOID, Value: eatBytes}},
	}
	peerCertDER, _ := x509.CreateCertificate(rand.Reader, peerTemplate, caCert, &peerKey.PublicKey, caKey)

	tempDir := t.TempDir()
	c := corim.NewUnsignedCorim()
	c.SetID("cocos-test-id")
	corimBytes, _ := c.ToCBOR()
	policyPath := filepath.Join(tempDir, "policy.cbor")
	_ = os.WriteFile(policyPath, corimBytes, 0o644)

	oldPolicyPath := attestation.AttestationPolicyPath
	attestation.AttestationPolicyPath = policyPath
	t.Cleanup(func() { attestation.AttestationPolicyPath = oldPolicyPath })

	err := verifier.VerifyPeerCertificate([][]byte{peerCertDER}, nil, nonce)
	assert.NoError(t, err)
}

func TestVerifyPeerCertificate_Failures_More(t *testing.T) {
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

	// Case 1: Invalid OID
	peerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	peerTemplate := &x509.Certificate{
		SerialNumber:    big.NewInt(4),
		NotBefore:       time.Now(),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{{Id: []int{1, 2, 3}, Value: []byte("val")}},
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, peerTemplate, caCert, &peerKey.PublicKey, caKey)
	err := verifier.VerifyPeerCertificate([][]byte{certDER}, nil, []byte("nonce"))
	assert.ErrorContains(t, err, "attestation extension not found")

	// Case 2: Policy path not set
	attestation.AttestationPolicyPath = ""
	peerPubKeyDER, _ := x509.MarshalPKIXPublicKey(&peerKey.PublicKey)
	nonce := []byte("nonce")
	teeNonce := append(peerPubKeyDER, nonce...)
	hashNonce := sha3.Sum512(teeNonce)
	claims := eat.EATClaims{Nonce: hashNonce[:], RawReport: []byte("rep")}
	eatBytes, _ := cbor.Marshal(claims)
	peerTemplate.ExtraExtensions = []pkix.Extension{{Id: SNPvTPMOID, Value: eatBytes}}
	certDERWithExt, _ := x509.CreateCertificate(rand.Reader, peerTemplate, caCert, &peerKey.PublicKey, caKey)

	err = verifier.VerifyPeerCertificate([][]byte{certDERWithExt}, nil, nonce)
	assert.ErrorContains(t, err, "attestation policy path is not set")
}
