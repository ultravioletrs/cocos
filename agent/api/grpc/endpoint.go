package grpc

import (
	"context"
	"encoding/json"

	"github.com/go-kit/kit/endpoint"
	"github.com/ultravioletrs/agent/agent"
)

func runEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(runReq)

		if err := req.validate(); err != nil {
			return runRes{}, err
		}

		var computation agent.Computation
		err := json.Unmarshal(req.Computation, &computation)
		if err != nil {
			return nil, err
		}

		computationStr, err := svc.Run(context.TODO(), computation)
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

		algorithmID, err := svc.Algo(ctx, req.Algorithm)
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

		datasetID, err := svc.Data(ctx, req.Dataset)
		if err != nil {
			return dataRes{}, err
		}

		return dataRes{DatasetID: datasetID}, nil
	}
}
