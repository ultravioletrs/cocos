// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package httpclient

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/ultravioletrs/cocos/pkg/clients"
)

func TestConfig_Configuration(t *testing.T) {
	config := clients.StandardClientConfig{
		BaseConfig: clients.BaseConfig{
			URL:          "http://localhost:8080",
			Timeout:      30 * time.Second,
			ClientCert:   "cert.pem",
			ClientKey:    "key.pem",
			ServerCAFile: "ca.pem",
		},
	}

	result := config.GetBaseConfig()

	assert.Equal(t, config, result)
	assert.Equal(t, "http://localhost:8080", result.URL)
	assert.Equal(t, 30*time.Second, result.Timeout)
	assert.Equal(t, "cert.pem", result.ClientCert)
	assert.Equal(t, "key.pem", result.ClientKey)
	assert.Equal(t, "ca.pem", result.ServerCAFile)
}

func TestAgentClientConfig_Configuration(t *testing.T) {
	agentConfig := &clients.AttestedClientConfig{
		BaseConfig: clients.BaseConfig{
			URL:          "https://agent.example.com",
			Timeout:      60 * time.Second,
			ClientCert:   "agent-cert.pem",
			ClientKey:    "agent-key.pem",
			ServerCAFile: "agent-ca.pem",
		},
		AttestationPolicy: "policy.json",
		AttestedTLS:       true,
		ProductName:       "Milan",
	}

	result := agentConfig.GetBaseConfig()

	assert.Equal(t, agentConfig.BaseConfig, result)
	assert.Equal(t, "https://agent.example.com", result.URL)
	assert.Equal(t, 60*time.Second, result.Timeout)
	assert.Equal(t, "agent-cert.pem", result.ClientCert)
	assert.Equal(t, "agent-key.pem", result.ClientKey)
	assert.Equal(t, "agent-ca.pem", result.ServerCAFile)
}

func TestProxyClientConfig_Configuration(t *testing.T) {
	proxyConfig := clients.StandardClientConfig{
		BaseConfig: clients.BaseConfig{
			URL:          "http://proxy.example.com",
			Timeout:      45 * time.Second,
			ClientCert:   "proxy-cert.pem",
			ClientKey:    "proxy-key.pem",
			ServerCAFile: "proxy-ca.pem",
		},
	}

	result := proxyConfig.BaseConfig

	assert.Equal(t, proxyConfig.BaseConfig, result)
	assert.Equal(t, "http://proxy.example.com", result.URL)
	assert.Equal(t, 45*time.Second, result.Timeout)
}

func TestNewClient_Success(t *testing.T) {
	tests := []struct {
		name   string
		config clients.ClientConfiguration
	}{
		{
			name: "Basic config",
			config: clients.BaseConfig{
				URL:     "http://localhost:8080",
				Timeout: 30 * time.Second,
			},
		},
		{
			name: "Agent config without attested TLS",
			config: &clients.AttestedClientConfig{
				BaseConfig: clients.BaseConfig{
					URL:     "https://agent.example.com",
					Timeout: 60 * time.Second,
				},
				AttestedTLS: false,
			},
		},
		{
			name: "Proxy config",
			config: clients.StandardClientConfig{
				BaseConfig: clients.BaseConfig{
					URL:     "http://proxy.example.com",
					Timeout: 45 * time.Second,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)

			assert.NoError(t, err)
			assert.NotNil(t, client)
			assert.NotNil(t, client.Transport())
			assert.Equal(t, tt.config.GetBaseConfig().Timeout, client.Timeout())
		})
	}
}

func TestClient_Transport(t *testing.T) {
	config := clients.BaseConfig{
		URL:     "http://localhost:8080",
		Timeout: 30 * time.Second,
	}

	client, err := NewClient(config)
	assert.NoError(t, err)

	transport := client.Transport()

	assert.NotNil(t, transport)
	assert.IsType(t, &http.Transport{}, transport)
	assert.Equal(t, 100, transport.MaxIdleConns)
	assert.Equal(t, 90*time.Second, transport.IdleConnTimeout)
	assert.Equal(t, 10*time.Second, transport.TLSHandshakeTimeout)
}

func TestClient_Secure(t *testing.T) {
	tests := []struct {
		name     string
		config   clients.ClientConfiguration
		expected string
	}{
		{
			name: "Without TLS",
			config: clients.StandardClientConfig{
				BaseConfig: clients.BaseConfig{
					URL:     "http://localhost:8080",
					Timeout: 30 * time.Second,
				},
			},
			expected: clients.WithoutTLS.String(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)
			assert.NoError(t, err)

			secure := client.Secure()
			assert.Equal(t, tt.expected, secure)
		})
	}
}

func TestClient_Timeout(t *testing.T) {
	expectedTimeout := 45 * time.Second
	config := clients.BaseConfig{
		URL:     "http://localhost:8080",
		Timeout: expectedTimeout,
	}

	client, err := NewClient(config)
	assert.NoError(t, err)

	timeout := client.Timeout()
	assert.Equal(t, expectedTimeout, timeout)
}

func TestCreateTransport_DefaultSettings(t *testing.T) {
	config := clients.BaseConfig{
		URL:     "http://localhost:8080",
		Timeout: 30 * time.Second,
	}

	transport, security, err := createTransport(config)

	assert.NoError(t, err)
	assert.NotNil(t, transport)
	assert.Equal(t, clients.WithoutTLS, security)
	assert.Equal(t, 100, transport.MaxIdleConns)
	assert.Equal(t, 90*time.Second, transport.IdleConnTimeout)
	assert.Equal(t, 10*time.Second, transport.TLSHandshakeTimeout)
	assert.Nil(t, transport.TLSClientConfig)
}

func TestCreateTransport_ATLSError(t *testing.T) {
	config := &clients.AttestedClientConfig{
		BaseConfig: clients.BaseConfig{
			URL:     "https://agent.example.com",
			Timeout: 60 * time.Second,
		},
		AttestationPolicy: "invalid",
		AttestedTLS:       true,
		ProductName:       "Milan",
	}

	transport, security, err := createTransport(config)

	assert.Error(t, err)
	assert.Nil(t, transport)
	assert.Equal(t, clients.WithoutTLS, security)
	assert.Contains(t, err.Error(), "failed to stat attestation policy")
}

func TestCreateTransport_BasicTLSError(t *testing.T) {
	config := clients.BaseConfig{
		URL:          "https://example.com",
		Timeout:      30 * time.Second,
		ServerCAFile: "invalid",
	}

	transport, security, err := createTransport(config)

	assert.Error(t, err)
	assert.Nil(t, transport)
	assert.Equal(t, clients.WithoutTLS, security)
	assert.Contains(t, err.Error(), "failed to load root ca file")
}

func TestClientInterface_Implementation(t *testing.T) {
	config := clients.BaseConfig{
		URL:     "http://localhost:8080",
		Timeout: 30 * time.Second,
	}

	client, err := NewClient(config)
	assert.NoError(t, err)

	// Verify that client implements the Client interface
	var _ Client = client

	// Test all interface methods
	assert.NotNil(t, client.Transport())
	assert.NotEmpty(t, client.Secure())
	assert.Greater(t, client.Timeout(), time.Duration(0))
}

func TestAgentClientConfig_FieldAccess(t *testing.T) {
	config := &clients.AttestedClientConfig{
		BaseConfig: clients.BaseConfig{
			URL:     "https://agent.example.com",
			Timeout: 60 * time.Second,
		},
		AttestationPolicy: "test-policy",
		AttestedTLS:       true,
		ProductName:       "TestProduct",
	}

	assert.Equal(t, "test-policy", config.AttestationPolicy)
	assert.True(t, config.AttestedTLS)
	assert.Equal(t, "TestProduct", config.ProductName)
	assert.Equal(t, "https://agent.example.com", config.URL)
	assert.Equal(t, 60*time.Second, config.Timeout)
}

func TestProxyClientConfig_FieldAccess(t *testing.T) {
	config := clients.StandardClientConfig{
		BaseConfig: clients.BaseConfig{
			URL:          "http://proxy.example.com",
			Timeout:      45 * time.Second,
			ClientCert:   "proxy-cert.pem",
			ClientKey:    "proxy-key.pem",
			ServerCAFile: "proxy-ca.pem",
		},
	}

	assert.Equal(t, "http://proxy.example.com", config.URL)
	assert.Equal(t, 45*time.Second, config.Timeout)
	assert.Equal(t, "proxy-cert.pem", config.ClientCert)
	assert.Equal(t, "proxy-key.pem", config.ClientKey)
	assert.Equal(t, "proxy-ca.pem", config.ServerCAFile)
}

func TestClientConfiguration_Interface(t *testing.T) {
	// Test that all config types implement ClientConfiguration interface
	var configs []clients.ClientConfiguration

	configs = append(configs, clients.BaseConfig{})
	configs = append(configs, &clients.AttestedClientConfig{})
	configs = append(configs, clients.StandardClientConfig{})

	for i, config := range configs {
		t.Run(t.Name()+"_"+string(rune(i+'0')), func(t *testing.T) {
			result := config.GetBaseConfig()
			assert.IsType(t, clients.BaseConfig{}, result)
		})
	}
}
