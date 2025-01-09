// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cvm

import (
	"github.com/ultravioletrs/cocos/agent/cvm"
	"github.com/ultravioletrs/cocos/pkg/clients/grpc"
)

// NewManagerClient creates new manager gRPC client instance.
func NewCVMClient(cfg grpc.CVMClientConfig) (grpc.Client, cvm.CVMServiceClient, error) {
	client, err := grpc.NewClient(cfg)
	if err != nil {
		return nil, nil, err
	}

	return client, cvm.NewCVMServiceClient(client.Connection()), nil
}
