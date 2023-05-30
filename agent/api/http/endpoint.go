// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	agent "github.com/ultravioletrs/agent/agent"
)

func pingEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(pingReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		greeting, err := svc.Ping(req.Secret)
		if err != nil {
			return nil, err
		}

		res := pingRes{
			Greeting: greeting,
		}
		return res, nil
	}
}

func runEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(runReq)

		if err := req.validate(); err != nil {
			return runRes{}, err
		}
		cmp := agent.Computation{
			ID:                 req.computation.ID,
			Name:               req.computation.Name,
			Description:        req.computation.Description,
			Status:             req.computation.Status,
			Owner:              req.computation.Owner,
			StartTime:          req.computation.StartTime,
			EndTime:            req.computation.EndTime,
			Datasets:           req.computation.Datasets,
			Algorithms:         req.computation.Algorithms,
			DatasetProviders:   req.computation.DatasetProviders,
			AlgorithmProviders: req.computation.AlgorithmProviders,
			ResultConsumers:    req.computation.ResultConsumers,
			Ttl:                req.computation.Ttl,
			Metadata:           req.computation.Metadata,
		}

		cmpStr, err := svc.Run(ctx, cmp)
		if err != nil {
			return runRes{}, err
		}

		return runRes{Computation: cmpStr}, nil
	}
}
