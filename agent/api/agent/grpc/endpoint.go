package grpc

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/ultravioletrs/agent/agent"
)

func runEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(runReq)

		if err := req.validate(); err != nil {
			return runRes{}, err
		}

		comp := agent.Computation{
			Name:               req.Name,
			Description:        req.Description,
			Owner:              req.Owner,
			Datasets:           req.Datasets,
			Algorithms:         req.Algorithms,
			DatasetProviders:   req.DatasetProviders,
			AlgorithmProviders: req.AlgorithmProviders,
			ResultConsumers:    req.ResultConsumers,
			Ttl:                req.TTL,
		}

		computation, err := svc.Run(context.TODO(), comp)
		if err != nil {
			return runRes{}, err
		}

		return runRes{Computation: computation}, nil
	}
}
