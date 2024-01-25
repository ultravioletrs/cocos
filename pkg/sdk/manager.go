// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package sdk

import (
	"context"
	"log/slog"

	"github.com/ultravioletrs/cocos/manager"
)

var _ manager.Service = (*managerSDK)(nil)

type managerSDK struct {
	client manager.ManagerServiceClient
	logger *slog.Logger
}

func NewManagerSDK(client manager.ManagerServiceClient, logger *slog.Logger) manager.Service {
	return &managerSDK{
		client: client,
		logger: logger,
	}
}

// Run deploys a new agent in a virtual machine.
func (sdk *managerSDK) Run(ctx context.Context, c *manager.Computation) (string, error) {
	request := &manager.RunRequest{
		Computation: c,
	}

	response, err := sdk.client.Run(ctx, request)
	if err != nil {
		sdk.logger.Error("Failed to call Run RPC")
		return "", err
	}

	return response.AgentAddress, nil
}
