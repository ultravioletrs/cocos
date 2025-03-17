// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"

	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos/manager"
	"github.com/ultravioletrs/cocos/pkg/attestation/cmdconfig"
	"github.com/ultravioletrs/cocos/pkg/clients/grpc"
	"github.com/ultravioletrs/cocos/pkg/clients/grpc/agent"
	managergrpc "github.com/ultravioletrs/cocos/pkg/clients/grpc/manager"
	"github.com/ultravioletrs/cocos/pkg/sdk"
)

var Verbose bool

type CLI struct {
	agentSDK      sdk.SDK
	agentConfig   grpc.AgentClientConfig
	managerConfig grpc.ManagerClientConfig
	client        grpc.Client
	managerClient manager.ManagerServiceClient
	connectErr    error
	measurement   cmdconfig.MeasurementProvider
}

func New(agentConfig grpc.AgentClientConfig, managerConfig grpc.ManagerClientConfig, measurement cmdconfig.MeasurementProvider) *CLI {
	return &CLI{
		agentConfig:   agentConfig,
		managerConfig: managerConfig,
		measurement:   measurement,
	}
}

func (c *CLI) InitializeAgentSDK(cmd *cobra.Command) error {
	agentGRPCClient, agentClient, err := agent.NewAgentClient(context.Background(), c.agentConfig)
	if err != nil {
		c.connectErr = err
		return err
	}
	cmd.Println("🔗 Connected to agent using ", agentGRPCClient.Secure())
	c.client = agentGRPCClient

	c.agentSDK = sdk.NewAgentSDK(agentClient)
	return nil
}

func (c *CLI) InitializeManagerClient(cmd *cobra.Command) error {
	managerGRPCClient, managerClient, err := managergrpc.NewManagerClient(c.managerConfig)
	if err != nil {
		c.connectErr = err
		return err
	}

	cmd.Println("🔗 Connected to manager using ", managerGRPCClient.Secure())
	c.client = managerGRPCClient

	c.managerClient = managerClient
	return nil
}

func (c *CLI) Close() {
	c.client.Close()
}
