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
	"fmt"
	"math/big"
	"time"

	"github.com/ultravioletrs/cocos/pkg/server"
)

// BuildServerTLSConfig prepares the base TLS configuration used by the EA/aTLS
// transport. If no certificate/key pair is configured, it falls back to an
// ephemeral self-signed identity bound by the exported authenticator.
func BuildServerTLSConfig(certFile, keyFile, serverCAFile, clientCAFile string) (*tls.Config, tls.Certificate, bool, error) {
	if certFile != "" || keyFile != "" {
		tlsSetup, err := server.SetupRegularTLS(certFile, keyFile, serverCAFile, clientCAFile)
		if err != nil {
			return nil, tls.Certificate{}, false, err
		}
		tlsSetup.Config.MinVersion = tls.VersionTLS13
		return tlsSetup.Config, tlsSetup.Config.Certificates[0], tlsSetup.MTLS, nil
	}

	identity, err := generateEphemeralIdentity()
	if err != nil {
		return nil, tls.Certificate{}, false, fmt.Errorf("failed to generate ephemeral TLS identity: %w", err)
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.NoClientCert,
		Certificates: []tls.Certificate{identity},
	}

	mtls, err := server.ConfigureCertificateAuthorities(tlsConfig, serverCAFile, clientCAFile)
	if err != nil {
		return nil, tls.Certificate{}, false, err
	}
	if mtls {
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig, identity, mtls, nil
}

func generateEphemeralIdentity() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "cocos-atls-ephemeral",
			Organization: []string{"Ultraviolet"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        template,
	}, nil
}
