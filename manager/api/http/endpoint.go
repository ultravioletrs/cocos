// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package http

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/ultravioletrs/cocos/manager"
	"github.com/ultravioletrs/cocos/pkg/clients/grpc"
)

func runEndpoint(svc manager.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(runReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		agentConf := grpc.Config{
			ClientTLS: req.ClientTLS,
			CACerts:   req.CACerts,
			Timeout:   req.Timeout.Duration,
		}
		// Call the Run method on the service
		runID, err := svc.Run(ctx, req.Computation, agentConf)
		if err != nil {
			return nil, err
		}

		// Create the response
		res := runRes{
			ID: runID,
		}

		return res, nil
	}
}
