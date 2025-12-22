// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package ingress

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ultravioletrs/cocos/agent"
)

// TestAgentConfigToProxyConfig tests conversion from AgentConfig to ProxyConfig.
func TestAgentConfigToProxyConfig(t *testing.T) {
	tests := []struct {
		name     string
		input    agent.AgentConfig
		expected ProxyConfig
	}{
		{
			name: "basic config without TLS",
			input: agent.AgentConfig{
				CertFile:     "",
				KeyFile:      "",
				ServerCAFile: "",
				ClientCAFile: "",
				AttestedTls:  false,
			},
			expected: ProxyConfig{
				Port:         "7002",
				CertFile:     "",
				KeyFile:      "",
				ServerCAFile: "",
				ClientCAFile: "",
				AttestedTLS:  false,
			},
		},
		{
			name: "config with regular TLS",
			input: agent.AgentConfig{
				CertFile:     "/path/to/cert.pem",
				KeyFile:      "/path/to/key.pem",
				ServerCAFile: "/path/to/server-ca.pem",
				ClientCAFile: "/path/to/client-ca.pem",
				AttestedTls:  false,
			},
			expected: ProxyConfig{
				Port:         "7002",
				CertFile:     "/path/to/cert.pem",
				KeyFile:      "/path/to/key.pem",
				ServerCAFile: "/path/to/server-ca.pem",
				ClientCAFile: "/path/to/client-ca.pem",
				AttestedTLS:  false,
			},
		},
		{
			name: "config with attested TLS",
			input: agent.AgentConfig{
				CertFile:     "",
				KeyFile:      "",
				ServerCAFile: "/path/to/server-ca.pem",
				ClientCAFile: "/path/to/client-ca.pem",
				AttestedTls:  true,
			},
			expected: ProxyConfig{
				Port:         "7002",
				CertFile:     "",
				KeyFile:      "",
				ServerCAFile: "/path/to/server-ca.pem",
				ClientCAFile: "/path/to/client-ca.pem",
				AttestedTLS:  true,
			},
		},
		{
			name: "config with mTLS",
			input: agent.AgentConfig{
				CertFile:     "/path/to/cert.pem",
				KeyFile:      "/path/to/key.pem",
				ServerCAFile: "/path/to/server-ca.pem",
				ClientCAFile: "/path/to/client-ca.pem",
				AttestedTls:  false,
			},
			expected: ProxyConfig{
				Port:         "7002",
				CertFile:     "/path/to/cert.pem",
				KeyFile:      "/path/to/key.pem",
				ServerCAFile: "/path/to/server-ca.pem",
				ClientCAFile: "/path/to/client-ca.pem",
				AttestedTLS:  false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := AgentConfigToProxyConfig(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestComputationToProxyContext tests conversion from Computation to ProxyContext.
func TestComputationToProxyContext(t *testing.T) {
	tests := []struct {
		name     string
		input    agent.Computation
		expected ProxyContext
	}{
		{
			name: "computation with name",
			input: agent.Computation{
				ID:          "comp-123",
				Name:        "test-computation",
				Description: "A test computation",
			},
			expected: ProxyContext{
				ID:   "comp-123",
				Name: "test-computation",
			},
		},
		{
			name: "computation without name",
			input: agent.Computation{
				ID:          "comp-456",
				Name:        "",
				Description: "Another test computation",
			},
			expected: ProxyContext{
				ID:   "comp-456",
				Name: "",
			},
		},
		{
			name: "computation with special characters in name",
			input: agent.Computation{
				ID:          "comp-789",
				Name:        "test-computation-with-dashes_and_underscores",
				Description: "Computation with special chars",
			},
			expected: ProxyContext{
				ID:   "comp-789",
				Name: "test-computation-with-dashes_and_underscores",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ComputationToProxyContext(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestAgentConfigToProxyConfigPortIsFixed tests that port is always set to 7002.
func TestAgentConfigToProxyConfigPortIsFixed(t *testing.T) {
	configs := []agent.AgentConfig{
		{},
		{CertFile: "/cert.pem", KeyFile: "/key.pem"},
		{AttestedTls: true},
	}

	for i, cfg := range configs {
		result := AgentConfigToProxyConfig(cfg)
		assert.Equal(t, "7002", result.Port, "Port should always be 7002 for config %d", i)
	}
}
