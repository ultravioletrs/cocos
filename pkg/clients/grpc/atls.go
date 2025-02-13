// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/ultravioletrs/cocos/pkg/atls"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"google.golang.org/grpc/credentials"
)

func setupATLS(cfg AgentClientConfig) (credentials.TransportCredentials, error) {
	err := ReadAttestationPolicy(cfg.AttestationPolicy, &quoteprovider.AttConfigurationSEVSNP)
	if err != nil {
		return nil, errors.Wrap(fmt.Errorf("failed to read Attestation Policy"), err)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: verifyPeerCertificateATLS,
	}
	return credentials.NewTLS(tlsConfig), nil
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

func verifyPeerCertificateATLS(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
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
