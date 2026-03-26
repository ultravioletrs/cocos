// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package internaltransport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "internal-transport"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}

func TestServerAllowsIdentityWithoutTLSConfig(t *testing.T) {
	cert := selfSignedCert(t)
	a, b := net.Pipe()

	serverTLS := tls.Server(a, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	})
	clientTLS := tls.Client(b, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	})

	type result struct {
		conn *Conn
		err  error
	}
	serverCh := make(chan result, 1)
	clientCh := make(chan result, 1)

	go func() {
		conn, err := Server(serverTLS, &ServerConfig{
			Identity: cert,
		})
		serverCh <- result{conn: conn, err: err}
	}()

	go func() {
		conn, err := Client(clientTLS, &ClientConfig{
			TLSConfig: &tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS13,
				MaxVersion:         tls.VersionTLS13,
			},
		})
		clientCh <- result{conn: conn, err: err}
	}()

	srvRes := <-serverCh
	cliRes := <-clientCh

	if srvRes.err != nil {
		t.Fatalf("server failed: %v", srvRes.err)
	}
	if cliRes.err != nil {
		t.Fatalf("client failed: %v", cliRes.err)
	}

	defer srvRes.conn.Close()
	defer cliRes.conn.Close()
}
