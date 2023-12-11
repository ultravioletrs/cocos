// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package http

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
			return nil, err
		}

		agentConf := grpc.Config{
			ClientTLS: req.ClientTLS,
			CACerts:   req.CACerts,
			Timeout:   req.Timeout.Duration,
		}
		if agentConf.Timeout == 0 {
			agentConf.Timeout = 60 * time.Second
		}

		mc := manager.Computation{
			Id:              req.Computation.ID,
			Name:            req.Computation.Name,
			Description:     req.Computation.Description,
			ResultConsumers: req.Computation.ResultConsumers,
			Timeout:         req.Computation.Timeout.String(),
		}
		for _, algo := range req.Computation.Algorithms {
			mc.Algorithms = append(mc.Algorithms, &manager.Algorithm{Id: algo.ID, Provider: algo.Provider})
		}
		for _, data := range req.Computation.Datasets {
			mc.Datasets = append(mc.Datasets, &manager.Dataset{Id: data.ID, Provider: data.Provider})
		}

		// Call the Run method on the service
		if err := svc.Run(ctx, &mc); err != nil {
			return nil, err
		}

		// Create the response
		res := runRes{}

		return res, nil
	}
}
