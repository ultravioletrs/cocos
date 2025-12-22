// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package ingress

import (
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
