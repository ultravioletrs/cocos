// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package http

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/ultravioletrs/cocos/manager"
)

func runEndpoint(svc manager.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(runReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		mc := manager.Computation{
			Id:              req.Computation.ID,
			Name:            req.Computation.Name,
			Description:     req.Computation.Description,
			ResultConsumers: req.Computation.ResultConsumers,
		}
		for _, algo := range req.Computation.Algorithms {
			mc.Algorithms = append(mc.Algorithms, &manager.Algorithm{Id: algo.ID, Provider: algo.Provider})
		}
		for _, data := range req.Computation.Datasets {
			mc.Datasets = append(mc.Datasets, &manager.Dataset{Id: data.ID, Provider: data.Provider})
		}

		// Call the Run method on the service
		agAddr, err := svc.Run(ctx, &mc)
		if err != nil {
			return nil, err
		}

		return runRes{AgentAddress: agAddr}, nil
	}
}
