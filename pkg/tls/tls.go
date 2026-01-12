// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package tls

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"

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

const AttestationReportSize = 0x4A0

var (
	ErrFailedToLoadClientCertKey  = errors.New("failed to load client certificate and key")
	ErrFailedToLoadRootCA         = errors.New("failed to load root ca file")
	errAttestationPolicyIrregular = errors.New("attestation policy file is not a regular file")
)

// Result contains the result of TLS configuration.
type Result struct {
	Config   *tls.Config
	Security Security
}

// LoadBasicConfig loads standard TLS configuration (TLS/mTLS).
func LoadBasicConfig(serverCAFile, clientCert, clientKey string) (*Result, error) {
	tlsConfig := &tls.Config{}
	security := WithoutTLS

	// If no TLS configuration is provided, return nil config (no TLS)
	if serverCAFile == "" && clientCert == "" && clientKey == "" {
		return &Result{Config: nil, Security: security}, nil
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

	return &Result{Config: tlsConfig, Security: security}, nil
}

// LoadATLSConfig configures Attested TLS.
// Parameters are passed individually to avoid circular dependencies with the clients package.
func LoadATLSConfig(attestationPolicy, serverCAFile, clientCert, clientKey string) (*Result, error) {
	security := WithATLS

	info, err := os.Stat(attestationPolicy)
	if err != nil {
		return nil, errors.Wrap(errors.New("failed to stat attestation policy file"), err)
	}

	if !info.Mode().IsRegular() {
		return nil, errAttestationPolicyIrregular
	}

	attestation.AttestationPolicyPath = attestationPolicy

	var rootCAs *x509.CertPool

	if serverCAFile != "" {
		rootCAs, err = loadRootCAs(serverCAFile)
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
			return atls.NewCertificateVerifier(rootCAs).VerifyPeerCertificate(rawCerts, verifiedChains, nonce)
		},
	}

	if clientCert != "" || clientKey != "" {
		certificate, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, errors.Wrap(ErrFailedToLoadClientCertKey, err)
		}

		tlsConfig.Certificates = []tls.Certificate{certificate}
	}

	return &Result{Config: tlsConfig, Security: security}, nil
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
