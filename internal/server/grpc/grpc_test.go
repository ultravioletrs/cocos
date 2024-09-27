// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	authmocks "github.com/ultravioletrs/cocos/agent/mocks"
	"github.com/ultravioletrs/cocos/agent/quoteprovider/mocks"
	"github.com/ultravioletrs/cocos/internal/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

var lis *bufconn.Listener

func init() {
	lis = bufconn.Listen(bufSize)
}

func TestNew(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := server.Config{
		Host: "localhost",
		Port: "50051",
	}
	logger := slog.Default()
	qp := new(mocks.QuoteProvider)
	authSvc := new(authmocks.Authenticator)

	srv := New(ctx, cancel, "TestServer", config, func(srv *grpc.Server) {}, logger, qp, authSvc)

	assert.NotNil(t, srv)
	assert.IsType(t, &Server{}, srv)
}

func TestServerStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := server.Config{
		Host: "localhost",
		Port: "0", // Use any available port
	}
	logger := slog.Default()
	qp := new(mocks.QuoteProvider)
	authSvc := new(authmocks.Authenticator)

	srv := New(ctx, cancel, "TestServer", config, func(srv *grpc.Server) {}, logger, qp, authSvc)

	go func() {
		err := srv.Start()
		assert.NoError(t, err)
	}()

	// Give the server some time to start
	time.Sleep(100 * time.Millisecond)

	err := srv.Stop()
	assert.NoError(t, err)
}

func TestServerStartWithTLS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cert, key, err := generateSelfSignedCert()
	assert.NoError(t, err)

	config := server.Config{
		Host:     "localhost",
		Port:     "0", // Use any available port
		CertFile: string(cert),
		KeyFile:  string(key),
	}
	logger := slog.Default()
	qp := new(mocks.QuoteProvider)
	authSvc := new(authmocks.Authenticator)

	srv := New(ctx, cancel, "TestServer", config, func(srv *grpc.Server) {}, logger, qp, authSvc)

	go func() {
		err := srv.Start()
		assert.NoError(t, err)
	}()

	// Give the server some time to start
	time.Sleep(100 * time.Millisecond)

	err = srv.Stop()
	assert.NoError(t, err)
}

func TestServerStartWithAttestedTLS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := server.Config{
		Host:        "localhost",
		Port:        "0", // Use any available port
		AttestedTLS: true,
	}
	logger := slog.Default()
	qp := new(mocks.QuoteProvider)
	authSvc := new(authmocks.Authenticator)
	qp.On("GetRawQuote", mock.Anything).Return([]byte("mock-quote"), nil)

	srv := New(ctx, cancel, "TestServer", config, func(srv *grpc.Server) {}, logger, qp, authSvc)

	go func() {
		err := srv.Start()
		assert.NoError(t, err)
	}()

	// Give the server some time to start
	time.Sleep(100 * time.Millisecond)

	err := srv.Stop()
	assert.NoError(t, err)

	qp.AssertExpectations(t)
}

func TestServerStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	config := server.Config{
		Host: "localhost",
		Port: "0", // Use any available port
	}
	logger := slog.Default()
	qp := new(mocks.QuoteProvider)
	authSvc := new(authmocks.Authenticator)

	srv := New(ctx, cancel, "TestServer", config, func(srv *grpc.Server) {}, logger, qp, authSvc)

	go func() {
		err := srv.Start()
		assert.NoError(t, err)
	}()

	// Give the server some time to start
	time.Sleep(100 * time.Millisecond)

	err := srv.Stop()
	assert.NoError(t, err)
}

func generateSelfSignedCert() ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	cert, err := generateSelfSignedCertFromKey(key)
	if err != nil {
		return nil, nil, err
	}

	return cert, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), nil
}

func generateSelfSignedCertFromKey(key *rsa.PrivateKey) ([]byte, error) {
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes}), nil
}