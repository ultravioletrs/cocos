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
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"github.com/ultravioletrs/cocos/pkg/server"
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

	config := server.AgentConfig{
		ServerConfig: server.ServerConfig{
			BaseConfig: server.BaseConfig{
				Host: "localhost",
				Port: "50051",
			},
		},
	}
	logger := slog.Default()
	authSvc := new(authmocks.Authenticator)

	srv := New(ctx, cancel, "TestServer", config, func(srv *grpc.Server) {}, logger, authSvc, "", "")

	assert.NotNil(t, srv)
	assert.IsType(t, &Server{}, srv)
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

	config := server.AgentConfig{
		ServerConfig: server.ServerConfig{
			BaseConfig: server.BaseConfig{
				Host:     "localhost",
				Port:     "0",
				CertFile: certFile.Name(),
				KeyFile:  keyFile.Name(),
			},
		},
	}

	logBuffer := &ThreadSafeBuffer{}
	logger := slog.New(slog.NewTextHandler(logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
	authSvc := new(authmocks.Authenticator)

	srv := New(ctx, cancel, "TestServer", config, func(srv *grpc.Server) {}, logger, authSvc, "", "")

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

func TestServerStartWithmTLSFile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	caCertFile, clientCertFile, clientKeyFile, err := createCertificatesFiles()
	assert.NoError(t, err)

	config := server.AgentConfig{
		ServerConfig: server.ServerConfig{
			BaseConfig: server.BaseConfig{
				Host:         "localhost",
				Port:         "0",
				CertFile:     string(clientCertFile),
				KeyFile:      string(clientKeyFile),
				ServerCAFile: caCertFile,
			},
		},
	}

	logBuffer := &ThreadSafeBuffer{}
	logger := slog.New(slog.NewTextHandler(logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
	authSvc := new(authmocks.Authenticator)

	srv := New(ctx, cancel, "TestServer", config, func(srv *grpc.Server) {}, logger, authSvc, "", "")

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

func TestServerStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	config := server.AgentConfig{
		ServerConfig: server.ServerConfig{
			BaseConfig: server.BaseConfig{
				Host: "localhost",
				Port: "0",
			},
		},
	}
	buf := &ThreadSafeBuffer{}
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	authSvc := new(authmocks.Authenticator)

	srv := New(ctx, cancel, "TestServer", config, func(srv *grpc.Server) {}, logger, authSvc, "", "")

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

func TestServerInitializationAndStartup(t *testing.T) {
	vtpm.ExternalTPM = &vtpm.DummyRWC{}

	testCases := []struct {
		name          string
		config        server.AgentConfig
		expectedLog   string
		expectError   bool
		setupCallback func(*testing.T, *server.AgentConfig, *ThreadSafeBuffer)
	}{
		{
			name: "Non-TLS Server Startup",
			config: server.AgentConfig{
				ServerConfig: server.ServerConfig{
					BaseConfig: server.BaseConfig{
						Host: "localhost",
						Port: "0",
					},
				},
			},
			expectedLog: "TestServer service gRPC server listening at localhost:0 without TLS",
		},
		{
			name: "TLS Server Startup with Self-Signed Certificate",
			config: server.AgentConfig{
				ServerConfig: server.ServerConfig{
					BaseConfig: server.BaseConfig{
						Host: "localhost",
						Port: "0",
					},
				},
			},
			setupCallback: setupTLSConfig,
			expectedLog:   "TestServer service gRPC server listening at localhost:0 with TLS",
		},
		{
			name: "TLS Server Startup with Invalid Certificates",
			config: server.AgentConfig{
				ServerConfig: server.ServerConfig{
					BaseConfig: server.BaseConfig{
						Host:     "localhost",
						Port:     "0",
						CertFile: "invalid",
						KeyFile:  "invalid",
					},
				},
			},
			expectError: true,
			expectedLog: "failed to load auth certificates",
		},
		{
			name: "maTLS Server Startup",
			config: server.AgentConfig{
				ServerConfig: server.ServerConfig{
					BaseConfig: server.BaseConfig{
						Host:         "localhost",
						Port:         "0",
						ServerCAFile: "",
						ClientCAFile: "",
					},
				},
				AttestedTLS: true,
			},
			setupCallback: setupMTLSConfig,
			expectError:   false,
			expectedLog:   "with Attested mTLS",
		},
		{
			name: "maTLS Server Startup with Invalid Server CA file",
			config: server.AgentConfig{
				ServerConfig: server.ServerConfig{
					BaseConfig: server.BaseConfig{
						Host:         "localhost",
						Port:         "0",
						ServerCAFile: "invalid",
					},
				},
				AttestedTLS: true,
			},
			setupCallback: setupInvalidRootCAConfig,
			expectError:   true,
			expectedLog:   "failed to load server ca file",
		},
		{
			name: "maTLS Server Startup with Invalid Clinet CA file",
			config: server.AgentConfig{
				ServerConfig: server.ServerConfig{
					BaseConfig: server.BaseConfig{
						Host:         "localhost",
						Port:         "0",
						ServerCAFile: "invalid",
					},
				},
				AttestedTLS: true,
			},
			setupCallback: setupInvalidClientCAConfig,
			expectError:   true,
			expectedLog:   "failed to load client ca file",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.setupCallback != nil {
				tc.setupCallback(t, &tc.config, nil)
			}

			logBuffer := &ThreadSafeBuffer{}
			logger := slog.New(slog.NewTextHandler(logBuffer, &slog.HandlerOptions{Level: slog.LevelDebug}))
			authSvc := new(authmocks.Authenticator)

			srv := New(ctx, cancel, "TestServer", tc.config, func(srv *grpc.Server) {}, logger, authSvc, "", "")
			var wg sync.WaitGroup
			wg.Add(1)

			go func() {
				wg.Done()
				err := srv.Start()
				if tc.expectError {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), tc.expectedLog)
				} else {
					assert.NoError(t, err)
				}
			}()

			wg.Wait()

			time.Sleep(200 * time.Millisecond)

			cancel()

			time.Sleep(200 * time.Millisecond)

			if !tc.expectError {
				logContent := logBuffer.String()
				fmt.Println(logContent)
				assert.Contains(t, logContent, tc.expectedLog)
			}
		})
	}
}

func setupTLSConfig(t *testing.T, config *server.AgentConfig, _ *ThreadSafeBuffer) {
	cert, key, err := generateSelfSignedCert()
	assert.NoError(t, err)

	config.CertFile = string(cert)
	config.KeyFile = string(key)
}

func setupMTLSConfig(t *testing.T, config *server.AgentConfig, _ *ThreadSafeBuffer) {
	cert, key, err := generateSelfSignedCert()
	assert.NoError(t, err)

	config.CertFile = string(cert)
	config.KeyFile = string(key)
	config.ServerCAFile = string(cert)
	config.ClientCAFile = string(cert)
}

func setupInvalidRootCAConfig(t *testing.T, config *server.AgentConfig, _ *ThreadSafeBuffer) {
	cert, key, err := generateSelfSignedCert()
	assert.NoError(t, err)

	config.CertFile = string(cert)
	config.KeyFile = string(key)
	config.ServerCAFile = "invalid"
	config.ClientCAFile = string(cert)
}

func setupInvalidClientCAConfig(t *testing.T, config *server.AgentConfig, _ *ThreadSafeBuffer) {
	cert, key, err := generateSelfSignedCert()
	assert.NoError(t, err)

	config.CertFile = string(cert)
	config.KeyFile = string(key)
	config.ClientCAFile = "invalid"
	config.ServerCAFile = string(cert)
}

func createCertificatesFiles() (string, string, string, error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", err
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

	caCertDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return "", "", "", err
	}

	caCertFile, err := createTempFile(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER}))
	if err != nil {
		return "", "", "", err
	}

	clientKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", err
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
		return "", "", "", err
	}

	clientCertFile, err := createTempFile(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER}))
	if err != nil {
		return "", "", "", err
	}

	clientKeyFile, err := createTempFile(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)}))
	if err != nil {
		return "", "", "", err
	}

	return caCertFile, clientCertFile, clientKeyFile, nil
}

func createTempFile(data []byte) (string, error) {
	file, err := createTempFileHandle()
	if err != nil {
		return "", err
	}

	_, err = file.Write(data)
	if err != nil {
		return "", err
	}

	err = file.Close()
	if err != nil {
		return "", err
	}

	return file.Name(), nil
}

func createTempFileHandle() (*os.File, error) {
	return os.CreateTemp("", "test")
}
