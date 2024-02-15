// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"github.com/ultravioletrs/cocos/pkg/clients/grpc"
	"github.com/ultravioletrs/cocos/pkg/manager"
)

// NewManagerClient creates new manager gRPC client instance.
func NewManagerClient(cfg grpc.Config) (grpc.Client, manager.ManagerServiceClient, error) {
	client, err := grpc.NewClient(cfg)
	if err != nil {
		return nil, nil, err
	}

	return client, manager.NewManagerServiceClient(client.Connection()), nil
}
