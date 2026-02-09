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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyPeerCertificate(t *testing.T) {
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

	verifier := NewCertificateVerifier(rootCAs)

	peerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	nonce := []byte("test-nonce")

	peerTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Peer"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	peerCertDER, err := x509.CreateCertificate(rand.Reader, peerTemplate, caCert, &peerKey.PublicKey, caKey)
	require.NoError(t, err)

	err = verifier.VerifyPeerCertificate([][]byte{peerCertDER}, nil, nonce)
	assert.ErrorContains(t, err, "attestation extension not found")
}

func TestVerifyPeerCertificate_Empty(t *testing.T) {
	verifier := NewCertificateVerifier(nil)
	err := verifier.VerifyPeerCertificate(nil, nil, nil)
	assert.ErrorContains(t, err, "no certificates provided")
}
