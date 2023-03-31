// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/ultravioletrs/manager/manager"
)

func createDomainEndpoint(svc manager.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(createDomainReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		name, err := svc.CreateDomain(req.Pool, req.Volume, req.Domain)
		if err != nil {
			return nil, err
		}

		res := createDomainRes{
			Name: name,
		}
		return res, nil
	}
}

func runEndpoint(svc manager.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(runReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		// Create the computation
		computation := manager.Computation{
			Name:               req.Name,
			Description:        req.Description,
			Status:             "",
			Owner:              req.Owner,
			Datasets:           req.Datasets,
			Algorithms:         req.Algorithms,
			DatasetProviders:   req.DatasetProviders,
			AlgorithmProviders: req.AlgorithmProviders,
			ResultConsumers:    req.ResultConsumers,
			TTL:                req.TTL,
			StartTime:          nil,
			EndTime:            nil,
		}

		// Call the Run method on the service
		runID, err := svc.Run(computation)
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
