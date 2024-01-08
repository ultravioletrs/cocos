// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/ultravioletrs/cocos/agent"
)

func runEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(runReq)

		if err := req.validate(); err != nil {
			return runRes{}, err
		}

		computation := agent.Computation{
			ID:              req.Computation.Id,
			Name:            req.Computation.Name,
			Description:     req.Computation.Description,
			Status:          req.Computation.Status,
			Owner:           req.Computation.Owner,
			StartTime:       req.Computation.StartTime.AsTime(),
			EndTime:         req.Computation.EndTime.AsTime(),
			ResultConsumers: req.Computation.ResultConsumers,
			Ttl:             req.Computation.Ttl,
		}

		for _, algo := range req.Computation.Algorithms {
			computation.Algorithms = append(computation.Algorithms, agent.Algorithm{ID: algo.Id, Provider: algo.Provider})
		}
		for _, data := range req.Computation.Datasets {
			computation.Datasets = append(computation.Datasets, agent.Dataset{ID: data.Id, Provider: data.Provider})
		}
		computation.Metadata = make(agent.Metadata)
		for k, v := range req.Computation.Metadata.Fields {
			if v != nil {
				computation.Metadata[k] = v.AsInterface()
			}
		}
		timeout, err := time.ParseDuration(req.Computation.Timeout)
		if err != nil {
			return runRes{}, err
		}
		computation.Timeout.Duration = timeout

		computationStr, err := svc.Run(ctx, computation)
		if err != nil {
			return runRes{}, err
		}

		return runRes{Computation: computationStr}, nil
	}
}

func algoEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(algoReq)

		if err := req.validate(); err != nil {
			return algoRes{}, err
		}

		algo := agent.Algorithm{Algorithm: req.Algorithm, Provider: req.Provider, ID: req.Id}

		algorithmID, err := svc.Algo(ctx, algo)
		if err != nil {
			return algoRes{}, err
		}

		return algoRes{AlgorithmID: algorithmID}, nil
	}
}

func dataEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(dataReq)

		if err := req.validate(); err != nil {
			return dataRes{}, err
		}

		dataset := agent.Dataset{Dataset: req.Dataset, Provider: req.Provider, ID: req.Id}

		datasetID, err := svc.Data(ctx, dataset)
		if err != nil {
			return dataRes{}, err
		}

		return dataRes{DatasetID: datasetID}, nil
	}
}

func resultEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(resultReq)

		if err := req.validate(); err != nil {
			return resultRes{}, err
		}
		file, err := svc.Result(ctx, req.Consumer)
		if err != nil {
			return resultRes{}, err
		}

		return resultRes{File: file}, nil
	}
}

func attestationEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(attestationReq)

		if err := req.validate(); err != nil {
			return attestationRes{}, err
		}
		file, err := svc.Attestation(ctx)
		if err != nil {
			return attestationRes{}, err
		}

		return attestationRes{File: file}, nil
	}
}
