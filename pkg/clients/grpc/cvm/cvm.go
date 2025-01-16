// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cvm

import (
	"github.com/ultravioletrs/cocos/agent/cvms"
	"github.com/ultravioletrs/cocos/pkg/clients/grpc"
)

// NewManagerClient creates new manager gRPC client instance.
func NewCVMClient(cfg grpc.CVMClientConfig) (grpc.Client, cvms.ServiceClient, error) {
	client, err := grpc.NewClient(cfg)
	if err != nil {
		return nil, nil, err
	}

	return client, cvms.NewServiceClient(client.Connection()), nil
}
