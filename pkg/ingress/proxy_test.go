// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package ingress

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/pkg/atls/mocks"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func createTempCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "server.crt")
	keyPath := filepath.Join(tmpDir, "server.key")

	certOut, err := os.Create(certPath)
	require.NoError(t, err)
	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	require.NoError(t, err)
	certOut.Close()

	keyOut, err := os.Create(keyPath)
	require.NoError(t, err)
	b, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	err = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	require.NoError(t, err)
	keyOut.Close()

	return certPath, keyPath
}

func getBackendURL() *url.URL {
	u, _ := url.Parse("http://localhost:8080")
	return u
}

// TestNewProxyServer tests the creation of a new proxy server.
func TestNewProxyServer(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ps := NewProxyServer(logger, getBackendURL(), nil)
	require.NotNil(t, ps)
}

// TestProxyStartStop tests basic start and stop operations.
func TestProxyStartStop(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ps := NewProxyServer(logger, getBackendURL(), nil)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	cfg := ProxyConfig{Port: fmt.Sprintf("%d", port)}
	ctx := ProxyContext{ID: "test-1", Name: "test-proxy"}

	err = ps.Start(cfg, ctx)
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)
	err = ps.Stop()
	require.NoError(t, err)
}

// TestProxyStartWithoutPort tests proxy without explicit port.
func TestProxyStartWithoutPort(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ps := NewProxyServer(logger, getBackendURL(), nil)

	cfg := ProxyConfig{Port: ""}
	ctx := ProxyContext{ID: "test-2"}

	err := ps.Start(cfg, ctx)
	require.NoError(t, err)
	defer func() { _ = ps.Stop() }()
	time.Sleep(100 * time.Millisecond)
}

// TestProxyStartAlreadyStarted tests error when starting twice.
func TestProxyStartAlreadyStarted(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ps := NewProxyServer(logger, getBackendURL(), nil)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	cfg := ProxyConfig{Port: fmt.Sprintf("%d", port)}
	ctx := ProxyContext{ID: "test-3"}

	err = ps.Start(cfg, ctx)
	require.NoError(t, err)
	defer func() { _ = ps.Stop() }()
	time.Sleep(100 * time.Millisecond)

	err = ps.Start(cfg, ctx)
	assert.Error(t, err)
	assert.Equal(t, "proxy server already started", err.Error())
}

// TestProxyStartAfterStopped tests error when starting after stop.
func TestProxyStartAfterStopped(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ps := NewProxyServer(logger, getBackendURL(), nil)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	cfg := ProxyConfig{Port: fmt.Sprintf("%d", port)}
	ctx := ProxyContext{ID: "test-4"}

	err = ps.Start(cfg, ctx)
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)
	err = ps.Stop()
	require.NoError(t, err)

	err = ps.Start(cfg, ctx)
	assert.Error(t, err)
	// After stop, attempts to start will fail with "already started" error first
	assert.Contains(t, err.Error(), "proxy server already")
}

// TestProxyWithName tests proxy context with name.
func TestProxyWithName(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ps := NewProxyServer(logger, getBackendURL(), nil)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	cfg := ProxyConfig{Port: fmt.Sprintf("%d", port)}
	ctx := ProxyContext{ID: "id-1", Name: "named-proxy"}

	err = ps.Start(cfg, ctx)
	require.NoError(t, err)
	defer func() { _ = ps.Stop() }()
	time.Sleep(100 * time.Millisecond)
}

// TestProxyWithoutName tests proxy context without name.
func TestProxyWithoutName(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ps := NewProxyServer(logger, getBackendURL(), nil)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	cfg := ProxyConfig{Port: fmt.Sprintf("%d", port)}
	ctx := ProxyContext{ID: "id-only"}

	err = ps.Start(cfg, ctx)
	require.NoError(t, err)
	defer func() { _ = ps.Stop() }()
	time.Sleep(100 * time.Millisecond)
}

// TestProxyMultipleStops tests multiple stop calls.
func TestProxyMultipleStops(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ps := NewProxyServer(logger, getBackendURL(), nil)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	cfg := ProxyConfig{Port: fmt.Sprintf("%d", port)}
	ctx := ProxyContext{ID: "test-multi-stop"}

	err = ps.Start(cfg, ctx)
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)

	err = ps.Stop()
	require.NoError(t, err)

	err = ps.Stop()
	require.NoError(t, err)
}

// TestProxyWithoutTLS tests proxy without TLS.
func TestProxyWithoutTLS(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ps := NewProxyServer(logger, getBackendURL(), nil)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	cfg := ProxyConfig{
		Port:        fmt.Sprintf("%d", port),
		AttestedTLS: false,
	}
	ctx := ProxyContext{ID: "test-no-tls"}

	err = ps.Start(cfg, ctx)
	require.NoError(t, err)
	defer func() { _ = ps.Stop() }()
	time.Sleep(100 * time.Millisecond)
}

func TestProxyWithUnixBackend(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create a temp directory for socket
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "backend.sock")

	// Start a dummy backend on unix socket
	l, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	defer l.Close()

	backendCalled := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendCalled = true
		w.WriteHeader(http.StatusOK)
	})

	h2s := &http2.Server{}
	h2cHandler := h2c.NewHandler(handler, h2s)

	go func() {
		_ = http.Serve(l, h2cHandler)
	}()

	// Configure proxy to use this unix socket
	backendURL, _ := url.Parse("unix://" + sockPath)
	ps := NewProxyServer(logger, backendURL, nil)

	// Find free port for proxy
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	cfg := ProxyConfig{
		Port: fmt.Sprintf("%d", port),
	}
	ctx := ProxyContext{ID: "test-unix"}

	err = ps.Start(cfg, ctx)
	require.NoError(t, err)
	defer func() { _ = ps.Stop() }()

	time.Sleep(100 * time.Millisecond)

	// Make request to proxy
	resp, err := http.Get(fmt.Sprintf("http://localhost:%d", port))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.True(t, backendCalled)
}

func TestProxyRegularTLS(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	certFile, keyFile := createTempCert(t)

	ps := NewProxyServer(logger, getBackendURL(), nil)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	cfg := ProxyConfig{
		Port:     fmt.Sprintf("%d", port),
		CertFile: certFile,
		KeyFile:  keyFile,
	}
	ctx := ProxyContext{ID: "test-tls"}

	err = ps.Start(cfg, ctx)
	require.NoError(t, err)
	defer func() { _ = ps.Stop() }()

	time.Sleep(100 * time.Millisecond)

	// Client with skipped verification
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get(fmt.Sprintf("https://localhost:%d", port))
	// Backend is not running/reachable so 502 or error is expected from reverse proxy,
	// but 502 means connection to proxy succeeded.
	// If the proxy itself was not working, we'd get connection refused or similar.
	require.NoError(t, err)
	if err == nil {
		resp.Body.Close()
	}
}

func TestProxyRegularTLSInvalidFiles(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ps := NewProxyServer(logger, getBackendURL(), nil)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	cfg := ProxyConfig{
		Port:     fmt.Sprintf("%d", port),
		CertFile: "non-existent.crt",
		KeyFile:  "non-existent.key",
	}
	ctx := ProxyContext{ID: "test-tls-fail"}

	err = ps.Start(cfg, ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to setup TLS")
}

func TestProxyAttestedTLS(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mockProvider := mocks.NewCertificateProvider(t)
	// We don't expect calls during Listen, only during handshake.
	// But Start logic doesn't block waiting for handshake.

	ps := NewProxyServer(logger, getBackendURL(), mockProvider)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	cfg := ProxyConfig{
		Port:        fmt.Sprintf("%d", port),
		AttestedTLS: true,
	}
	ctx := ProxyContext{ID: "test-attested-tls"}

	err = ps.Start(cfg, ctx)
	require.NoError(t, err)
	defer func() { _ = ps.Stop() }()
}

func TestProxyAttestedTLSMissingProvider(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ps := NewProxyServer(logger, getBackendURL(), nil)

	cfg := ProxyConfig{
		Port:        "0",
		AttestedTLS: true,
	}
	ctx := ProxyContext{ID: "test-attested-fail"}

	err := ps.Start(cfg, ctx)
	assert.Error(t, err)
	assert.Equal(t, "attested TLS requested but no certificate provider available", err.Error())
}

func TestProxyMTLS(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	certFile, _ := createTempCert(t)

	mockProvider := mocks.NewCertificateProvider(t)

	ps := NewProxyServer(logger, getBackendURL(), mockProvider)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	// Test case: AttestedTLS with ClientCAFile (mTLS)
	// server.ConfigureCertificateAuthorities reads the file.
	cfg := ProxyConfig{
		Port:         fmt.Sprintf("%d", port),
		AttestedTLS:  true,
		ClientCAFile: certFile, // Use self-signed cert as CA
		ServerCAFile: certFile, // Also for server CA
	}
	ctx := ProxyContext{ID: "test-mtls"}

	err = ps.Start(cfg, ctx)
	require.NoError(t, err)
	defer func() { _ = ps.Stop() }()
}

func TestProxyRegularMTLS(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	certFile, keyFile := createTempCert(t)

	ps := NewProxyServer(logger, getBackendURL(), nil)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	cfg := ProxyConfig{
		Port:         fmt.Sprintf("%d", port),
		CertFile:     certFile,
		KeyFile:      keyFile,
		ServerCAFile: certFile,
		ClientCAFile: certFile,
	}
	ctx := ProxyContext{ID: "test-regular-mtls"}

	err = ps.Start(cfg, ctx)
	require.NoError(t, err)
	defer func() { _ = ps.Stop() }()
}

func TestProxyAttestedTLSInvalidCA(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mockProvider := mocks.NewCertificateProvider(t)

	ps := NewProxyServer(logger, getBackendURL(), mockProvider)

	cfg := ProxyConfig{
		Port:         "0",
		AttestedTLS:  true,
		ServerCAFile: "non-existent.pem",
	}
	ctx := ProxyContext{ID: "test-attested-invalid-ca"}

	err := ps.Start(cfg, ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to configure certificate authorities")
}
