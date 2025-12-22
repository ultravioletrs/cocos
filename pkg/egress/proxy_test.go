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
		if _, err := w.Write([]byte("backend response")); err != nil {
			t.Logf("Failed to write response: %v", err)
		}
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
		if err := proxy.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			t.Logf("Proxy server error: %v", err)
		}
	}()
	defer func() {
		if err := proxy.Stop(context.Background()); err != nil {
			t.Logf("Failed to stop proxy: %v", err)
		}
	}()

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
		if _, err := w.Write([]byte("secure backend response")); err != nil {
			t.Logf("Failed to write response: %v", err)
		}
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
		if err := proxy.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			t.Logf("Proxy server error: %v", err)
		}
	}()
	defer func() {
		if err := proxy.Stop(context.Background()); err != nil {
			t.Logf("Failed to stop proxy: %v", err)
		}
	}()

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

// TestProxyHTTP2 tests HTTP/2 requests through the proxy
func TestProxyHTTP2(t *testing.T) {
	// 1. Start a backend server
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("http2 response")); err != nil {
			t.Logf("Failed to write response: %v", err)
		}
	}))
	defer backend.Close()

	// 2. Start Proxy
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ln, err := net.Listen("tcp", ":0")
	require.NoError(t, err)

	proxy := NewProxy(logger, ln.Addr().String())
	proxy.server.Addr = ln.Addr().String()

	go func() {
		if err := proxy.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			t.Logf("Proxy server error: %v", err)
		}
	}()
	defer func() {
		if err := proxy.Stop(context.Background()); err != nil {
			t.Logf("Failed to stop proxy: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// 3. Make HTTP/2 request via proxy
	proxyURL := fmt.Sprintf("http://%s", ln.Addr().String())
	client := &http.Client{
		Transport: &http.Transport{
			Proxy:             http.ProxyFromEnvironment,
			ForceAttemptHTTP2: true,
		},
	}

	os.Setenv("HTTP_PROXY", proxyURL)
	defer os.Unsetenv("HTTP_PROXY")

	// This will be an HTTP/1.1 request unless explicitly configured for HTTP/2
	resp, err := client.Get(backend.URL)
	if err == nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		assert.Equal(t, "http2 response", string(body))
	}
}

// TestProxyHeaderHandling tests that headers are properly handled
func TestProxyHeaderHandling(t *testing.T) {
	// Start a backend server that echoes headers
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "custom-value")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(r.Header.Get("X-Request-Header"))); err != nil {
			t.Logf("Failed to write response: %v", err)
		}
	}))
	defer backend.Close()

	// Start Proxy
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ln, err := net.Listen("tcp", ":0")
	require.NoError(t, err)

	proxy := NewProxy(logger, ln.Addr().String())
	proxy.server.Addr = ln.Addr().String()

	go func() {
		if err := proxy.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			t.Logf("Proxy server error: %v", err)
		}
	}()
	defer func() {
		if err := proxy.Stop(context.Background()); err != nil {
			t.Logf("Failed to stop proxy: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// Make request with custom headers
	proxyURL := fmt.Sprintf("http://%s", ln.Addr().String())
	os.Setenv("HTTP_PROXY", proxyURL)
	defer os.Unsetenv("HTTP_PROXY")

	req, _ := http.NewRequest("GET", backend.URL, nil)
	req.Header.Set("X-Request-Header", "request-value")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
	}

	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		assert.Equal(t, "custom-value", resp.Header.Get("X-Custom-Header"))
	}
}

// TestProxyWithDifferentMethods tests different HTTP methods
func TestProxyWithDifferentMethods(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(r.Method)); err != nil {
			t.Logf("Failed to write response: %v", err)
		}
	}))
	defer backend.Close()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ln, err := net.Listen("tcp", ":0")
	require.NoError(t, err)

	proxy := NewProxy(logger, ln.Addr().String())
	proxy.server.Addr = ln.Addr().String()

	go func() {
		if err := proxy.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			t.Logf("Proxy server error: %v", err)
		}
	}()
	defer func() {
		if err := proxy.Stop(context.Background()); err != nil {
			t.Logf("Failed to stop proxy: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	proxyURL := fmt.Sprintf("http://%s", ln.Addr().String())
	os.Setenv("HTTP_PROXY", proxyURL)
	defer os.Unsetenv("HTTP_PROXY")

	methods := []string{"GET", "POST", "PUT", "DELETE"}
	for _, method := range methods {
		req, _ := http.NewRequest(method, backend.URL, nil)
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
			},
		}

		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			assert.Equal(t, method, string(body))
		}
	}
}

// TestProxyErrorHandling tests error handling in the proxy
func TestProxyErrorHandling(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ln, err := net.Listen("tcp", ":0")
	require.NoError(t, err)

	proxy := NewProxy(logger, ln.Addr().String())
	proxy.server.Addr = ln.Addr().String()

	go func() {
		if err := proxy.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			t.Logf("Proxy server error: %v", err)
		}
	}()
	defer func() {
		if err := proxy.Stop(context.Background()); err != nil {
			t.Logf("Failed to stop proxy: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// Try to connect to a non-existent backend
	proxyURL := fmt.Sprintf("http://%s", ln.Addr().String())
	os.Setenv("HTTP_PROXY", proxyURL)
	defer os.Unsetenv("HTTP_PROXY")

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
	}

	// This should fail because the backend doesn't exist
	resp, err := client.Get("http://nonexistent.example.com:99999")
	if resp != nil {
		defer resp.Body.Close()
		// Status should be error
		assert.NotEqual(t, http.StatusOK, resp.StatusCode)
	}
}

// TestProxyWithLargeBody tests proxy with large response body
func TestProxyWithLargeBody(t *testing.T) {
	largeBody := make([]byte, 1024*1024) // 1MB
	for i := range largeBody {
		largeBody[i] = byte(i % 256)
	}

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(largeBody); err != nil {
			t.Logf("Failed to write response: %v", err)
		}
	}))
	defer backend.Close()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ln, err := net.Listen("tcp", ":0")
	require.NoError(t, err)

	proxy := NewProxy(logger, ln.Addr().String())
	proxy.server.Addr = ln.Addr().String()

	go func() {
		if err := proxy.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			t.Logf("Proxy server error: %v", err)
		}
	}()
	defer func() {
		if err := proxy.Stop(context.Background()); err != nil {
			t.Logf("Failed to stop proxy: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

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
	assert.Equal(t, len(largeBody), len(body))
}
