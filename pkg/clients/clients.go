// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package clients

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/ultravioletrs/cocos/pkg/atls"
	"github.com/ultravioletrs/cocos/pkg/attestation"
)

// Security represents the type of TLS security configuration.
type Security int

const (
	WithoutTLS Security = iota
	WithTLS
	WithMTLS
	WithATLS
	WithMATLS
)

// String returns a human-readable representation of the security level.
func (s Security) String() string {
	switch s {
	case WithTLS:
		return "with TLS"
	case WithMTLS:
		return "with mTLS"
	case WithATLS:
		return "with aTLS"
	case WithMATLS:
		return "with maTLS"
	case WithoutTLS:
		return "without TLS"
	default:
		return "without TLS"
	}
}

const (
	AttestationReportSize = 0x4A0
)

var (
	ErrFailedToLoadClientCertKey  = errors.New("failed to load client certificate and key")
	ErrFailedToLoadRootCA         = errors.New("failed to load root ca file")
	errCertificateParse           = errors.New("failed to parse x509 certificate")
	errAttVerification            = errors.New("certificate is not self signed")
	errAttestationPolicyIrregular = errors.New("attestation policy file is not a regular file")
)

// BaseConfig contains common TLS configuration fields.
type BaseConfig struct {
	ClientCert   string
	ClientKey    string
	ServerCAFile string
}

// ATLSConfig contains configuration specific to Attested TLS.
type ATLSConfig struct {
	BaseConfig
	AttestationPolicy string
	ProductName       string
}

// TLSResult contains the result of TLS configuration.
type TLSResult struct {
	Config   *tls.Config
	Security Security
}

// LoadBasicTLSConfig loads standard TLS configuration (TLS/mTLS).
func LoadBasicTLSConfig(serverCAFile, clientCert, clientKey string) (*TLSResult, error) {
	tlsConfig := &tls.Config{}
	security := WithoutTLS

	// If no TLS configuration is provided, return nil config (no TLS)
	if serverCAFile == "" && clientCert == "" && clientKey == "" {
		return &TLSResult{Config: nil, Security: security}, nil
	}

	if serverCAFile != "" {
		rootCA, err := os.ReadFile(serverCAFile)
		if err != nil {
			return nil, errors.Wrap(ErrFailedToLoadRootCA, err)
		}

		if len(rootCA) > 0 {
			capool := x509.NewCertPool()
			if !capool.AppendCertsFromPEM(rootCA) {
				return nil, errors.New("failed to append root ca to tls.Config")
			}

			tlsConfig.RootCAs = capool
			security = WithTLS
		}
	}

	if clientCert != "" || clientKey != "" {
		certificate, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, errors.Wrap(ErrFailedToLoadClientCertKey, err)
		}

		tlsConfig.Certificates = []tls.Certificate{certificate}
		security = WithMTLS
	}

	return &TLSResult{Config: tlsConfig, Security: security}, nil
}

// LoadATLSConfig configures Attested TLS.
func LoadATLSConfig(cfg ATLSConfig) (*TLSResult, error) {
	security := WithATLS

	info, err := os.Stat(cfg.AttestationPolicy)
	if err != nil {
		return nil, errors.Wrap(errors.New("failed to stat attestation policy file"), err)
	}

	if !info.Mode().IsRegular() {
		return nil, errAttestationPolicyIrregular
	}

	attestation.AttestationPolicyPath = cfg.AttestationPolicy

	var rootCAs *x509.CertPool

	if cfg.ServerCAFile != "" {
		rootCAs, err = loadRootCAs(cfg.ServerCAFile)
		if err != nil {
			return nil, err
		}
		security = WithMATLS
	}

	nonce := make([]byte, 64)
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.Wrap(errors.New("failed to generate nonce"), err)
	}

	encoded := hex.EncodeToString(nonce)
	sni := encoded + ".nonce"

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		RootCAs:            rootCAs,
		ServerName:         sni,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return VerifyPeerCertificateATLS(rawCerts, verifiedChains, nonce, rootCAs)
		},
	}

	if cfg.ClientCert != "" || cfg.ClientKey != "" {
		certificate, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, errors.Wrap(ErrFailedToLoadClientCertKey, err)
		}

		tlsConfig.Certificates = []tls.Certificate{certificate}
	}

	return &TLSResult{Config: tlsConfig, Security: security}, nil
}

// loadRootCAs loads root CA certificates from a file.
func loadRootCAs(serverCAFile string) (*x509.CertPool, error) {
	// Read the certificate file
	certPEM, err := os.ReadFile(serverCAFile)
	if err != nil {
		return nil, errors.Wrap(errors.New("failed to read certificate file"), err)
	}

	// Decode the PEM block
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(errors.New("failed to parse certificate"), err)
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(cert)

	return rootCAs, nil
}

// VerifyPeerCertificateATLS verifies peer certificates for Attested TLS.
func VerifyPeerCertificateATLS(rawCerts [][]byte, _ [][]*x509.Certificate, nonce []byte, rootCAs *x509.CertPool) error {
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return errors.Wrap(errCertificateParse, err)
	}

	err = VerifyCertificateSignature(cert, rootCAs)
	if err != nil {
		return errors.Wrap(errAttVerification, err)
	}

	for _, ext := range cert.Extensions {
		pType, err := atls.GetPlatformTypeFromOID(ext.Id)
		if err == nil {
			pubKeyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
			if err != nil {
				return fmt.Errorf("failed to marshal public key to DER format: %w", err)
			}

			return atls.VerifyCertificateExtension(ext.Value, pubKeyDER, nonce, pType)
		}
	}

	return errors.New("attestation extension not found in certificate")
}

// VerifyCertificateSignature verifies the certificate signature against root CAs.
func VerifyCertificateSignature(cert *x509.Certificate, rootCAs *x509.CertPool) error {
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
		rootCAs.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Roots:       rootCAs,
		CurrentTime: time.Now(),
	}

	if _, err := cert.Verify(opts); err != nil {
		return err
	}

	return nil
}
