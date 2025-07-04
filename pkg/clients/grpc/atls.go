// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/ultravioletrs/cocos/pkg/atls"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"google.golang.org/grpc/credentials"
)

func setupATLS(cfg AgentClientConfig) (credentials.TransportCredentials, security, error) {
	security := withaTLS

	info, err := os.Stat(cfg.AttestationPolicy)
	if err != nil {
		return nil, withoutTLS, errors.Wrap(fmt.Errorf("failed to stat attestation policy file"), err)
	}

	if !info.Mode().IsRegular() {
		return nil, withoutTLS, fmt.Errorf("attestation policy file is not a regular file: %s", cfg.AttestationPolicy)
	}

	attestation.AttestationPolicyPath = cfg.AttestationPolicy

	var insecureSkipVerify bool = true
	var rootCAs *x509.CertPool = nil

	if len(cfg.ServerCAFile) > 0 {
		insecureSkipVerify = false

		// Read the certificate file
		certPEM, err := os.ReadFile(cfg.ServerCAFile)
		if err != nil {
			return nil, withoutTLS, errors.Wrap(fmt.Errorf("failed to read certificate file"), err)
		}

		// Decode the PEM block
		block, _ := pem.Decode(certPEM)
		if block == nil {
			return nil, withoutTLS, fmt.Errorf("failed to decode PEM block")
		}

		// Parse the certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, withoutTLS, errors.Wrap(fmt.Errorf("failed to parse certificate"), err)
		}

		rootCAs = x509.NewCertPool()
		rootCAs.AddCert(cert)

		security = withmaTLS
	}

	nonce := make([]byte, 64)
	if _, err := rand.Read(nonce); err != nil {
		return nil, withoutTLS, errors.Wrap(fmt.Errorf("failed to generate nonce"), err)
	}

	encoded := hex.EncodeToString(nonce)
	sni := fmt.Sprintf("%s.nonce", encoded)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
		RootCAs:            rootCAs,
		ServerName:         sni,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return verifyPeerCertificateATLS(rawCerts, verifiedChains, cfg, nonce)
		},
	}

	if cfg.ClientCert != "" || cfg.ClientKey != "" {
		certificate, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, withoutTLS, errors.Wrap(errFailedToLoadClientCertKey, err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}

	return credentials.NewTLS(tlsConfig), security, nil
}

func verifyPeerCertificateATLS(rawCerts [][]byte, verifiedChains [][]*x509.Certificate, cfg AgentClientConfig, nonce []byte) error {
	if len(cfg.ServerCAFile) > 0 {
		return nil
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return errors.Wrap(errCertificateParse, err)
	}

	err = checkIfCertificateSelfSigned(cert)
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

	return fmt.Errorf("attestation extension not found in certificate")
}

func checkIfCertificateSelfSigned(cert *x509.Certificate) error {
	certPool := x509.NewCertPool()
	certPool.AddCert(cert)

	opts := x509.VerifyOptions{
		Roots:       certPool,
		CurrentTime: time.Now(),
	}

	if _, err := cert.Verify(opts); err != nil {
		return err
	}

	return nil
}
