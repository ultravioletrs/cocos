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
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/absmach/certs"
	sdk "github.com/absmach/certs/sdk"
	"github.com/ultravioletrs/cocos/pkg/attestation"
)

// CertificateProvider defines the interface for providing TLS certificates.
type CertificateProvider interface {
	GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error)
}

// AttestedCertificateProvider provides attested TLS certificates.
type attestedCertificateProvider struct {
	attestationProvider AttestationProvider
	certsSDK            sdk.SDK
	agentToken          string
	subject             CertificateSubject
	useCA               bool
	cvmID               string
	ttl                 time.Duration
	notAfterYears       int
}

// NewAttestedProvider creates a new attested certificate provider for self-signed certificates.
func NewAttestedProvider(
	attestationProvider AttestationProvider,
	subject CertificateSubject,
) CertificateProvider {
	return &attestedCertificateProvider{
		attestationProvider: attestationProvider,
		subject:             subject,
		useCA:               false,
		notAfterYears:       defaultNotAfterYears,
	}
}

// NewAttestedCAProvider creates a new attested certificate provider for CA-signed certificates.
func NewAttestedCAProvider(
	attestationProvider AttestationProvider,
	subject CertificateSubject,
	certsSDK sdk.SDK, cvmID, agentToken string,
) CertificateProvider {
	return &attestedCertificateProvider{
		attestationProvider: attestationProvider,
		subject:             subject,
		certsSDK:            certsSDK,
		agentToken:          agentToken,
		useCA:               true,
		cvmID:               cvmID,
		ttl:                 time.Hour * 24 * 365, // Default 1 year
	}
}

// SetTTL sets the certificate TTL for CA-signed certificates.
func (p *attestedCertificateProvider) SetTTL(ttl time.Duration) {
	p.ttl = ttl
}

func (p *attestedCertificateProvider) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	pubKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	nonce, err := extractNonceFromSNI(clientHello.ServerName)
	if err != nil {
		return nil, fmt.Errorf("failed to extract nonce: %w", err)
	}

	attestationData, err := p.attestationProvider.Attest(pubKeyDER, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to get attestation: %w", err)
	}

	extension := pkix.Extension{
		Id:    p.attestationProvider.OID(),
		Value: attestationData,
	}

	var certDERBytes []byte
	if p.useCA {
		certDERBytes, err = p.generateCASignedCertificate(privateKey, extension)
	} else {
		certDERBytes, err = p.generateSelfSignedCertificate(privateKey, extension)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDERBytes},
		PrivateKey:  privateKey,
	}, nil
}

func (p *attestedCertificateProvider) generateSelfSignedCertificate(privateKey *ecdsa.PrivateKey, extension pkix.Extension) ([]byte, error) {
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Organization:  []string{p.subject.Organization},
			Country:       []string{p.subject.Country},
			Province:      []string{p.subject.Province},
			Locality:      []string{p.subject.Locality},
			StreetAddress: []string{p.subject.StreetAddress},
			PostalCode:    []string{p.subject.PostalCode},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(p.notAfterYears, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{extension},
	}

	return x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
}

func (p *attestedCertificateProvider) generateCASignedCertificate(privateKey *ecdsa.PrivateKey, extension pkix.Extension) ([]byte, error) {
	csrMetadata := certs.CSRMetadata{
		Organization:    []string{p.subject.Organization},
		Country:         []string{p.subject.Country},
		Province:        []string{p.subject.Province},
		Locality:        []string{p.subject.Locality},
		StreetAddress:   []string{p.subject.StreetAddress},
		PostalCode:      []string{p.subject.PostalCode},
		ExtraExtensions: []pkix.Extension{extension},
	}

	csr, sdkerr := sdk.CreateCSR(csrMetadata, privateKey)
	if sdkerr != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", sdkerr)
	}

	cert, err := p.certsSDK.IssueFromCSRInternal(p.cvmID, p.ttl.String(), string(csr.CSR), p.agentToken)
	if err != nil {
		return nil, err
	}

	cleanCertificateString := strings.ReplaceAll(cert.Certificate, "\\n", "\n")
	block, rest := pem.Decode([]byte(cleanCertificateString))

	if len(rest) != 0 {
		return nil, fmt.Errorf("failed to decode certificate PEM: unexpected remaining data")
	}
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM: no PEM block found")
	}

	return block.Bytes, nil
}

func NewProvider(provider attestation.Provider, platformType attestation.PlatformType, agentToken, cvmID string, certsSDK sdk.SDK) (CertificateProvider, error) {
	attestationProvider, err := NewAttestationProvider(provider, platformType)
	if err != nil {
		return nil, fmt.Errorf("failed to create attestation provider: %w", err)
	}

	subject := DefaultCertificateSubject()

	if certsSDK != nil {
		return NewAttestedCAProvider(attestationProvider, subject, certsSDK, cvmID, agentToken), nil
	}

	return NewAttestedProvider(attestationProvider, subject), nil
}
