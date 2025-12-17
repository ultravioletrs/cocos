// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package egress

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxyHTTP(t *testing.T) {
	// 1. Start a backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("backend response"))
	}))
	defer backend.Close()

	// 2. Start Proxy
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	proxy := NewProxy(logger, ":0")

	// Listen on a random port
	ln, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	proxy.server.Addr = ln.Addr().String()

	go func() {
		proxy.server.Serve(ln)
	}()
	defer proxy.Stop(context.Background())

	// waiting for server start
	time.Sleep(100 * time.Millisecond)

	// 3. Make request via proxy
	proxyURL := fmt.Sprintf("http://%s", ln.Addr().String())

	os.Setenv("HTTP_PROXY", proxyURL)
	defer os.Unsetenv("HTTP_PROXY")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
	}

	resp, err := client.Get(backend.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "backend response", string(body))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestProxyConnect(t *testing.T) {
	// 1. Start a backend TLS server
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("secure backend response"))
	}))
	defer backend.Close()

	// 2. Start Proxy
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	// Listen on a random port
	ln, err := net.Listen("tcp", ":0")
	require.NoError(t, err)

	proxy := NewProxy(logger, ln.Addr().String())
	proxy.server.Addr = ln.Addr().String()

	go func() {
		proxy.server.Serve(ln)
	}()
	defer proxy.Stop(context.Background())

	time.Sleep(100 * time.Millisecond)

	// 3. Configure client to use proxy
	proxyURL := fmt.Sprintf("http://%s", ln.Addr().String())
	os.Setenv("HTTPS_PROXY", proxyURL)
	defer os.Unsetenv("HTTPS_PROXY")

	client := backend.Client() // This client trusts the test cert
	// But we need to update its transport proxy
	if transport, ok := client.Transport.(*http.Transport); ok {
		transport.Proxy = http.ProxyFromEnvironment
	} else {
		// Create new transport if needed, but backend.Client() returns transport with TLS config
		tr := &http.Transport{
			TLSClientConfig: client.Transport.(*http.Transport).TLSClientConfig,
			Proxy:           http.ProxyFromEnvironment,
		}
		client.Transport = tr
	}

	resp, err := client.Get(backend.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "secure backend response", string(body))
}
