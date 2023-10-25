// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"github.com/ultravioletrs/agent/agent"
	agentapi "github.com/ultravioletrs/agent/agent/api/grpc"
	"github.com/ultravioletrs/cocos-ai/pkg/clients/grpc"
)

// NewAgentClient creates new agent gRPC client instance.
func NewAgentClient(cfg grpc.Config) (grpc.Client, agent.AgentServiceClient, error) {
	client, err := grpc.NewClient(cfg)
	if err != nil {
		return nil, nil, err
	}

	return client, agentapi.NewClient(client.Connection(), cfg.Timeout), nil
}
