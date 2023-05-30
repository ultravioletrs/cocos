package grpc

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/ultravioletrs/manager/manager"
)

func createDomainEndpoint(svc manager.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(createDomainReq)

		if err := req.validate(); err != nil {
			return createDomainRes{}, err
		}

		name, err := svc.CreateDomain(req.Pool, req.Volume, req.Domain)
		if err != nil {
			return createDomainRes{}, err
		}

		return createDomainRes{Name: name}, nil
	}
}

func runEndpoint(svc manager.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(runReq)

		if err := req.validate(); err != nil {
			return runRes{}, err
		}

		id, err := svc.Run(req.Computation)
		if err != nil {
			return runRes{}, err
		}

		return runRes{ID: id}, nil
	}
}
