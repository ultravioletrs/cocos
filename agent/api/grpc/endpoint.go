// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/ultravioletrs/cocos/agent"
)

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

func statusEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		status, err := svc.Status(ctx)
		if err != nil {
			return statusRes{}, err
		}

		return statusRes{Status: status}, nil
	}
}
