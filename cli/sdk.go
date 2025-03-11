// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/ultravioletrs/cocos/manager"
	"github.com/ultravioletrs/cocos/pkg/attestation/igvmmeasure"
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
	measurement   igvmmeasure.MeasurementProvider
}

func New(agentConfig grpc.AgentClientConfig, managerConfig grpc.ManagerClientConfig) *CLI {
	return &CLI{
		agentConfig:   agentConfig,
		managerConfig: managerConfig,
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

func (c *CLI) RunMeasurement(filePathToMeasure string, igvmBinaryPath string) error {
	if c.measurement == nil {
		measurement, err := igvmmeasure.NewIgvmMeasurement(filePathToMeasure, os.Stderr, os.Stdout)
		if err != nil {
			return fmt.Errorf("failed to initialize measurement: %w", err)
		}
		c.measurement = measurement
	}
	return c.measurement.Run(igvmBinaryPath)
}

func (c *CLI) Close() {
	c.client.Close()
}
