// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package ingress

import "github.com/ultravioletrs/cocos/agent"

// AgentConfigToProxyConfig converts agent.AgentConfig to ProxyConfig.
func AgentConfigToProxyConfig(cfg agent.AgentConfig) ProxyConfig {
	return ProxyConfig{
		Port:         "7002", // Ingress-proxy always uses port 7002
		CertFile:     cfg.CertFile,
		KeyFile:      cfg.KeyFile,
		ServerCAFile: cfg.ServerCAFile,
		ClientCAFile: cfg.ClientCAFile,
		AttestedTLS:  cfg.AttestedTls,
	}
}

// ComputationToProxyContext converts agent.Computation to ProxyContext.
func ComputationToProxyContext(cmp agent.Computation) ProxyContext {
	return ProxyContext{
		ID:   cmp.ID,
		Name: cmp.Name,
	}
}
