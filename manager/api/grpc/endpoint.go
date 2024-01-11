// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/ultravioletrs/cocos/manager"
	"github.com/ultravioletrs/cocos/pkg/clients/grpc"
)

func runEndpoint(svc manager.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(runReq)

		if err := req.validate(); err != nil {
			return runRes{}, err
		}

		agentConf := grpc.Config{
			ClientTLS: req.ClientTLS,
			CACerts:   req.CACerts,
			Timeout:   req.Timeout,
		}
		if agentConf.Timeout == 0 {
			agentConf.Timeout = 60 * time.Second
		}

		agAddr, err := svc.Run(ctx, req.Computation)
		if err != nil {
			return runRes{}, err
		}

		return runRes{AgentAddress: agAddr}, nil
	}
}
