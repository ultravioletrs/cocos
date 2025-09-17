// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/pkg/server"
)

// Mock implementations for testing.
type mockHandler struct {
	mock.Mock
}

func (m *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("test response")); err != nil {
		panic(err)
	}
}

type mockBaseConfig struct {
	certFile     string
	keyFile      string
	serverCAFile string
	clientCAFile string
	host         string
	port         string
}

func (m *mockBaseConfig) GetCertFile() string     { return m.certFile }
func (m *mockBaseConfig) GetKeyFile() string      { return m.keyFile }
func (m *mockBaseConfig) GetServerCAFile() string { return m.serverCAFile }
func (m *mockBaseConfig) GetClientCAFile() string { return m.clientCAFile }

type mockServerConfig struct {
	baseConfig *mockBaseConfig
}

func (m *mockServerConfig) GetHost() string { return "localhost" }
func (m *mockServerConfig) GetPort() string { return "8080" }
func (m *mockServerConfig) GetBaseConfig() server.ServerConfig {
	return server.ServerConfig{Config: server.Config{CertFile: m.baseConfig.certFile, KeyFile: m.baseConfig.keyFile, ServerCAFile: m.baseConfig.serverCAFile, ClientCAFile: m.baseConfig.clientCAFile, Host: m.baseConfig.host, Port: m.baseConfig.port}}
}

func TestNewServer(t *testing.T) {
	ctx := context.Background()
	cancel := func() {}
	name := "test-server"
	config := &mockServerConfig{
		baseConfig: &mockBaseConfig{},
	}
	handler := &mockHandler{}
	logger := slog.Default()
	caURL := "https://ca.example.com"

	server := NewServer(ctx, cancel, name, config, handler, logger, caURL)

	assert.NotNil(t, server)
	httpSrv, ok := server.(*httpServer)
	require.True(t, ok)
	assert.Equal(t, caURL, httpSrv.caURL)
	assert.NotNil(t, httpSrv.server)
	assert.Equal(t, handler, httpSrv.server.Handler)
}

func TestHttpServer_shouldUseAttestedTLS(t *testing.T) {
	tests := []struct {
		name        string
		config      server.ServerConfiguration
		caURL       string
		attestedTLS bool
		expected    bool
	}{
		{
			name: "should use attested TLS when config is AgentConfig and AttestedTLS is true and caURL is not empty",
			config: server.AgentConfig{
				AttestedTLS: true,
			},
			caURL:    "https://ca.example.com",
			expected: true,
		},
		{
			name: "should not use attested TLS when caURL is empty",
			config: server.AgentConfig{
				AttestedTLS: true,
			},
			caURL:    "",
			expected: false,
		},
		{
			name: "should not use attested TLS when AttestedTLS is false",
			config: server.AgentConfig{
				AttestedTLS: false,
			},
			caURL:    "https://ca.example.com",
			expected: false,
		},
		{
			name: "should not use attested TLS when config is not AgentConfig",
			config: &mockServerConfig{
				baseConfig: &mockBaseConfig{},
			},
			caURL:    "https://ca.example.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			cancel := func() {}

			server := NewServer(ctx, cancel, "test", tt.config, &mockHandler{}, slog.Default(), tt.caURL)
			httpSrv := server.(*httpServer)

			result := httpSrv.shouldUseAttestedTLS()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHttpServer_shouldUseRegularTLS(t *testing.T) {
	tests := []struct {
		name     string
		certFile string
		keyFile  string
		expected bool
	}{
		{
			name:     "should use regular TLS when both cert and key files are provided",
			certFile: "cert.pem",
			keyFile:  "key.pem",
			expected: true,
		},
		{
			name:     "should use regular TLS when only cert file is provided",
			certFile: "cert.pem",
			keyFile:  "",
			expected: true,
		},
		{
			name:     "should use regular TLS when only key file is provided",
			certFile: "",
			keyFile:  "key.pem",
			expected: true,
		},
		{
			name:     "should not use regular TLS when neither cert nor key files are provided",
			certFile: "",
			keyFile:  "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			cancel := func() {}
			config := &mockServerConfig{
				baseConfig: &mockBaseConfig{
					certFile: tt.certFile,
					keyFile:  tt.keyFile,
				},
			}

			server := NewServer(ctx, cancel, "test", config, &mockHandler{}, slog.Default(), "")
			httpSrv := server.(*httpServer)

			result := httpSrv.shouldUseRegularTLS()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHttpServer_Stop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	config := &mockServerConfig{
		baseConfig: &mockBaseConfig{},
	}
	handler := &mockHandler{}

	server := NewServer(ctx, cancel, "test-server", config, handler, slog.Default(), "")
	httpSrv := server.(*httpServer)

	// Start a test server that we can control
	testServer := httptest.NewServer(handler)
	defer testServer.Close()

	// Replace the server's HTTP server with our test server's
	httpSrv.server = testServer.Config

	err := httpSrv.Stop()
	assert.NoError(t, err)
}

func TestHttpServer_logAttestedTLSStart(t *testing.T) {
	tests := []struct {
		name string
		mtls bool
	}{
		{
			name: "log attested mTLS start",
			mtls: true,
		},
		{
			name: "log attested TLS start",
			mtls: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			cancel := func() {}
			config := &mockServerConfig{
				baseConfig: &mockBaseConfig{},
			}

			server := NewServer(ctx, cancel, "test-server", config, &mockHandler{}, slog.Default(), "")
			httpSrv := server.(*httpServer)

			// This test mainly ensures the method doesn't panic
			// In a real scenario, you might want to capture log output
			assert.NotPanics(t, func() {
				httpSrv.logAttestedTLSStart(tt.mtls)
			})
		})
	}
}

func TestHttpServer_logRegularTLSStart(t *testing.T) {
	tests := []struct {
		name string
		mtls bool
	}{
		{
			name: "log regular mTLS start",
			mtls: true,
		},
		{
			name: "log regular TLS start",
			mtls: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			cancel := func() {}
			config := &mockServerConfig{
				baseConfig: &mockBaseConfig{
					certFile:     "cert.pem",
					keyFile:      "key.pem",
					serverCAFile: "server-ca.pem",
					clientCAFile: "client-ca.pem",
				},
			}

			server := NewServer(ctx, cancel, "test-server", config, &mockHandler{}, slog.Default(), "")
			httpSrv := server.(*httpServer)

			// This test mainly ensures the method doesn't panic
			assert.NotPanics(t, func() {
				httpSrv.logRegularTLSStart(tt.mtls)
			})
		})
	}
}

func TestHttpServer_startWithoutTLS(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	config := &mockServerConfig{
		baseConfig: &mockBaseConfig{},
	}
	handler := &mockHandler{}

	server := NewServer(ctx, cancel, "test-server", config, handler, slog.Default(), "")
	httpSrv := server.(*httpServer)

	// Use a test server to avoid binding to actual ports
	testServer := httptest.NewServer(handler)
	defer testServer.Close()

	httpSrv.server = testServer.Config

	err := httpSrv.startWithoutTLS()
	// The error will be related to context cancellation or server shutdown
	assert.Error(t, err)
}

func TestHttpServer_Protocol(t *testing.T) {
	tests := []struct {
		name          string
		setupTLS      func(*httpServer)
		expectedProto string
	}{
		{
			name: "HTTP protocol without TLS",
			setupTLS: func(s *httpServer) {
				s.Protocol = httpProtocol
			},
			expectedProto: httpProtocol,
		},
		{
			name: "HTTPS protocol with TLS",
			setupTLS: func(s *httpServer) {
				s.Protocol = httpsProtocol
				s.server.TLSConfig = &tls.Config{}
			},
			expectedProto: httpsProtocol,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			cancel := func() {}
			config := &mockServerConfig{
				baseConfig: &mockBaseConfig{},
			}

			server := NewServer(ctx, cancel, "test-server", config, &mockHandler{}, slog.Default(), "")
			httpSrv := server.(*httpServer)

			tt.setupTLS(httpSrv)

			assert.Equal(t, tt.expectedProto, httpSrv.Protocol)
		})
	}
}

func TestHttpServer_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	config := &mockServerConfig{
		baseConfig: &mockBaseConfig{},
	}
	handler := &mockHandler{}

	server := NewServer(ctx, cancel, "test-server", config, handler, slog.Default(), "")
	httpSrv := server.(*httpServer)

	// Cancel the context immediately
	cancel()

	// The listenAndServe method should handle context cancellation
	err := httpSrv.listenAndServe(false)
	assert.NoError(t, err) // Should return no error when context is cancelled and Stop() succeeds
}

func TestHttpServer_TLSConfiguration(t *testing.T) {
	ctx := context.Background()
	cancel := func() {}
	config := &mockServerConfig{
		baseConfig: &mockBaseConfig{
			certFile: "cert.pem",
			keyFile:  "key.pem",
		},
	}

	server := NewServer(ctx, cancel, "test-server", config, &mockHandler{}, slog.Default(), "")
	httpSrv := server.(*httpServer)

	// Test TLS configuration setup
	httpSrv.server.TLSConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	assert.NotNil(t, httpSrv.server.TLSConfig)
	assert.Equal(t, uint16(tls.VersionTLS12), httpSrv.server.TLSConfig.MinVersion)
}

// Integration-style test for server lifecycle.
func TestHttpServer_Lifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	config := &mockServerConfig{
		baseConfig: &mockBaseConfig{
			host: "localhost",
			port: "8080",
		},
	}
	handler := &mockHandler{}

	server := NewServer(ctx, cancel, "test-server", config, handler, slog.Default(), "")

	// Test that server can be created and has expected initial state
	httpSrv, ok := server.(*httpServer)
	require.True(t, ok)
	assert.NotNil(t, httpSrv.server)
	assert.Equal(t, "localhost:8080", httpSrv.server.Addr)

	// Test Stop without Start (should not panic)
	err := httpSrv.Stop()
	assert.NoError(t, err)
}
