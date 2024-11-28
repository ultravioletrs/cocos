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
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	authmocks "github.com/ultravioletrs/cocos/agent/auth/mocks"
	"github.com/ultravioletrs/cocos/internal/server"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider/mocks"
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
	buf := &ThreadSafeBuffer{}
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

	time.Sleep(200 * time.Millisecond)

	cancel()

	time.Sleep(200 * time.Millisecond)

	logContent := logBuffer.String()
	fmt.Println(logContent)
	assert.Contains(t, logContent, "TestServer service gRPC server listening at localhost:0 with TLS")
}

func TestServerStartWithTLSInvalidCerts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	config := server.Config{
		Host:     "localhost",
		Port:     "0",
		CertFile: string("invalid"),
		KeyFile:  string("invalid"),
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
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load auth certificates")
	}()

	wg.Wait()

	time.Sleep(200 * time.Millisecond)

	cancel()

	time.Sleep(200 * time.Millisecond)
}

func TestServerStartWithTLSFile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	cert, key, err := generateSelfSignedCert()
	assert.NoError(t, err)

	certFile, err := os.CreateTemp("", "cert*.pem")
	assert.NoError(t, err)

	keyFile, err := os.CreateTemp("", "key*.pem")
	assert.NoError(t, err)

	t.Cleanup(func() {
		os.Remove(certFile.Name())
		os.Remove(keyFile.Name())
	})

	_, err = certFile.Write(cert)
	assert.NoError(t, err)

	_, err = keyFile.Write(key)
	assert.NoError(t, err)

	err = certFile.Close()
	assert.NoError(t, err)
	err = keyFile.Close()
	assert.NoError(t, err)

	config := server.Config{
		Host:     "localhost",
		Port:     "0",
		CertFile: certFile.Name(),
		KeyFile:  keyFile.Name(),
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

	time.Sleep(200 * time.Millisecond)

	cancel()

	time.Sleep(200 * time.Millisecond)

	logContent := logBuffer.String()
	fmt.Println(logContent)
	assert.Contains(t, logContent, "TestServer service gRPC server listening at localhost:0 with TLS")
}

func TestServerStartWithmTLS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	cert, key, err := generateSelfSignedCert()
	assert.NoError(t, err)

	config := server.Config{
		Host:         "localhost",
		Port:         "0",
		CertFile:     string(cert),
		KeyFile:      string(key),
		ServerCAFile: string(cert),
		ClientCAFile: string(cert),
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

	time.Sleep(200 * time.Millisecond)

	cancel()

	time.Sleep(200 * time.Millisecond)

	logContent := logBuffer.String()
	fmt.Println(logContent)
	assert.Contains(t, logContent, "TestServer service gRPC server listening at localhost:0 with TLS")
}

func TestServerStartWithmTLSIvalidRootCA(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	cert, key, err := generateSelfSignedCert()
	assert.NoError(t, err)

	config := server.Config{
		Host:         "localhost",
		Port:         "0",
		CertFile:     string(cert),
		KeyFile:      string(key),
		ServerCAFile: string("invalid"),
		ClientCAFile: string(cert),
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
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to append root ca to tls.Config")
	}()

	wg.Wait()

	time.Sleep(200 * time.Millisecond)

	cancel()

	time.Sleep(200 * time.Millisecond)
}

func TestServerStartWithmTLSClientCA(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	cert, key, err := generateSelfSignedCert()
	assert.NoError(t, err)

	config := server.Config{
		Host:         "localhost",
		Port:         "0",
		CertFile:     string(cert),
		KeyFile:      string(key),
		ServerCAFile: string(cert),
		ClientCAFile: string("invalid"),
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
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to append client ca to tls.Config")
	}()

	wg.Wait()

	time.Sleep(200 * time.Millisecond)

	cancel()

	time.Sleep(200 * time.Millisecond)
}

func TestServerStartWithmTLSFile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	cert, key, err := generateSelfSignedCert()
	assert.NoError(t, err)

	certFile, err := os.CreateTemp("", "cert*.pem")
	assert.NoError(t, err)

	keyFile, err := os.CreateTemp("", "key*.pem")
	assert.NoError(t, err)

	t.Cleanup(func() {
		os.Remove(certFile.Name())
		os.Remove(keyFile.Name())
	})

	_, err = certFile.Write(cert)
	assert.NoError(t, err)

	_, err = keyFile.Write(key)
	assert.NoError(t, err)

	err = certFile.Close()
	assert.NoError(t, err)
	err = keyFile.Close()
	assert.NoError(t, err)

	config := server.Config{
		Host:         "localhost",
		Port:         "0",
		CertFile:     certFile.Name(),
		KeyFile:      keyFile.Name(),
		ServerCAFile: certFile.Name(),
		ClientCAFile: certFile.Name(),
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

	time.Sleep(200 * time.Millisecond)

	cancel()

	time.Sleep(200 * time.Millisecond)

	logContent := logBuffer.String()
	fmt.Println(logContent)
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

	time.Sleep(1000 * time.Millisecond)

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
	buf := &ThreadSafeBuffer{}
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
