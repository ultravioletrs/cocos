// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/ultravioletrs/cocos/pkg/atls"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"google.golang.org/grpc/credentials"
)

func setupATLS(cfg AgentClientConfig) (credentials.TransportCredentials, security, error) {
	security := withaTLS
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

	tlsConfig := &tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
		RootCAs:            rootCAs,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return verifyPeerCertificateATLS(rawCerts, verifiedChains, cfg)
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

func CustomDialer(ctx context.Context, addr string) (net.Conn, error) {
	ip, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("could not create a custom dialer")
	}

	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("bad format of IP address: %v", err)
	}

	conn, err := atls.DialTLSClient(ip, p)
	if err != nil {
		return nil, fmt.Errorf("could not create TLS connection")
	}

	return conn, nil
}

func verifyPeerCertificateATLS(rawCerts [][]byte, verifiedChains [][]*x509.Certificate, cfg AgentClientConfig) error {
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

	return nil
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
