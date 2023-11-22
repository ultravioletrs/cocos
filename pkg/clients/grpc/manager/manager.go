// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"github.com/ultravioletrs/cocos/manager"
	managerapi "github.com/ultravioletrs/cocos/manager/api/grpc"
	"github.com/ultravioletrs/cocos/pkg/clients/grpc"
)

// NewManagerClient creates new manager gRPC client instance.
func NewManagerClient(cfg grpc.Config) (grpc.Client, manager.ManagerServiceClient, error) {
	client, err := grpc.NewClient(cfg)
	if err != nil {
		return nil, nil, err
	}

	return client, managerapi.NewClient(client.Connection(), cfg.Timeout), nil
}
