// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"strings"
	"sync"
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

	config := server.Config{
		Host: "localhost",
		Port: "0",
	}
	buf := new(bytes.Buffer)
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	qp := new(mocks.QuoteProvider)
	authSvc := new(authmocks.Authenticator)

	srv := New(ctx, cancel, "TestServer", config, func(srv *grpc.Server) {}, logger, qp, authSvc)

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		wg.Done()
		err := srv.Start()
		assert.NoError(t, err)
	}()

	wg.Wait()

	time.Sleep(100 * time.Millisecond)

	cancel()

	assert.Contains(t, buf.String(), "TestServer service gRPC server listening at localhost:0 without TLS")
}

func TestServerStartWithTLS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	cert, key, err := generateSelfSignedCert()
	assert.NoError(t, err)

	config := server.Config{
		Host:     "localhost",
		Port:     "0",
		CertFile: string(cert),
		KeyFile:  string(key),
	}

	logBuffer := &ThreadSafeBuffer{}
	logger := slog.New(slog.NewTextHandler(logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
	qp := new(mocks.QuoteProvider)
	authSvc := new(authmocks.Authenticator)

	srv := New(ctx, cancel, "TestServer", config, func(srv *grpc.Server) {}, logger, qp, authSvc)

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		wg.Done()
		err := srv.Start()
		assert.NoError(t, err)
	}()

	wg.Wait()

	time.Sleep(100 * time.Millisecond)

	cancel()

	time.Sleep(100 * time.Millisecond)

	logContent := logBuffer.String()
	assert.Contains(t, logContent, "TestServer service gRPC server listening at localhost:0 with TLS")
}

func TestServerStartWithAttestedTLS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	config := server.Config{
		Host:        "localhost",
		Port:        "0",
		AttestedTLS: true,
	}

	logBuffer := &ThreadSafeBuffer{}
	logger := slog.New(slog.NewTextHandler(logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
	qp := new(mocks.QuoteProvider)
	authSvc := new(authmocks.Authenticator)
	qp.On("GetRawQuote", mock.Anything).Return([]byte("mock-quote"), nil)

	srv := New(ctx, cancel, "TestServer", config, func(srv *grpc.Server) {}, logger, qp, authSvc)

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		wg.Done()
		err := srv.Start()
		assert.NoError(t, err)
	}()

	wg.Wait()

	time.Sleep(100 * time.Millisecond)

	cancel()

	time.Sleep(100 * time.Millisecond)

	logContent := logBuffer.String()
	assert.Contains(t, logContent, "TestServer service gRPC server listening at localhost:0 with Attested TLS")

	qp.AssertExpectations(t)
}

func TestServerStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	config := server.Config{
		Host: "localhost",
		Port: "0",
	}
	buf := new(bytes.Buffer)
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	qp := new(mocks.QuoteProvider)
	authSvc := new(authmocks.Authenticator)

	srv := New(ctx, cancel, "TestServer", config, func(srv *grpc.Server) {}, logger, qp, authSvc)

	go func() {
		err := srv.Start()
		assert.NoError(t, err)
	}()

	time.Sleep(100 * time.Millisecond)

	cancel()

	time.Sleep(100 * time.Millisecond)

	err := srv.Stop()
	assert.NoError(t, err)

	assert.Contains(t, buf.String(), "TestServer gRPC service shutdown at localhost:0")
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

type ThreadSafeBuffer struct {
	buffer strings.Builder
	mu     sync.Mutex
}

func (b *ThreadSafeBuffer) Write(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *ThreadSafeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}
