// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package atls

import (
	"testing"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestListen(t *testing.T) {
	cert := []byte("dummy_cert")
	key := []byte("dummy_key")

	cases := []struct {
		name    string
		address string
		err     error
	}{
		{
			name:    "Valid address",
			address: "127.0.0.1:8889",
			err:     nil,
		},
		{
			name:    "Invalid address format",
			address: "127.0.0.1",
			err:     errListener,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l, err := Listen(c.address, cert, key)
			assert.True(t, errors.Contains(err, c.err))
			if l != nil {
				t.Cleanup(func() {
					err := l.Close()
					assert.NoError(t, err)
				})
			}
		})
	}
}

func TestATLSServerListener_Accept(t *testing.T) {
	t.Run("Accepts connection", func(t *testing.T) {
		listener, err := Listen("127.0.0.1:8887", []byte("dummy_cert"), []byte("dummy_key"))
		assert.NoError(t, err)
		t.Cleanup(func() {
			err := listener.Close()
			assert.NoError(t, err)
		})
		conn, err := listener.Accept()
		assert.NoError(t, err)
		assert.NotNil(t, conn)
	})
}

/*func TestATLSConn_Read(t *testing.T) {
	cert, key, err := createCertificatesFiles()
	assert.NoError(t, err)
	l, err := Listen("127.0.0.1:8888", cert, key)
	assert.NoError(t, err)
	t.Cleanup(func() {
		err := l.Close()
		assert.NoError(t, err)
	})
	conn, err := l.Accept()
	t.Cleanup(func() {
		err := conn.Close()
		assert.NoError(t, err)
	})
	assert.NoError(t, err)
	buffer := make([]byte, 1024)

	t.Run("Successful read", func(t *testing.T) {
		n, err := conn.Read(buffer)
		assert.NoError(t, err)
		assert.True(t, n > 0)
	})

	t.Run("Read with nil connection", func(t *testing.T) {
		conn := &ATLSConn{tlsConn: nil}
		_, err := conn.Read(buffer)
		assert.Error(t, err)
		assert.Equal(t, err, errConnFailed)
	})
}

func createCertificatesFiles() ([]byte, []byte, error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	clientTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	clientCertDER, err := x509.CreateCertificate(rand.Reader, &clientTemplate, &caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)}), nil
}*/
