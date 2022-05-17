package api

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/ultravioletrs/cocos/computations"
)

func create(svc computations.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(createReq)
		if err := req.validate(); err != nil {
			return createRes{}, err
		}
		uid, err := svc.CreateComputation(ctx, req.token, req.computation)
		if err != nil {
			return createRes{}, err
		}
		ret := createRes{
			ID:      uid,
			created: true,
		}
		return ret, nil
	}
}

func view(svc computations.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(viewReq)
		if err := req.validate(); err != nil {
			return viewRes{}, err
		}
		computation, err := svc.ViewComputation(ctx, req.token, req.id)
		if err != nil {
			return createRes{}, err
		}
		ret := viewRes{
			Computation: computation,
		}

		return ret, nil
	}
}

func list(svc computations.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listReq)
		if err := req.validate(); err != nil {
			return listRes{}, err
		}
		res, err := svc.ListComputations(ctx, req.token, req.meta)
		if err != nil {
			return listRes{}, err
		}
		ret := listRes{
			Page: res,
		}
		return ret, nil
	}
}

func updateComputationEndpoint(svc computations.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		computation := computations.Computation{
			ID:          req.id,
			Name:        req.Name,
			Description: req.Description,
		}

		if err := svc.UpdateComputation(ctx, req.token, computation); err != nil {
			return nil, err
		}

		res := createRes{ID: req.id, created: false}
		return res, nil
	}
}

func remove(svc computations.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(viewReq)

		err := req.validate()
		if err == errors.ErrNotFound {
			return removeRes{}, nil
		}

		if err != nil {
			return nil, err
		}

		if err := svc.RemoveComputation(ctx, req.token, req.id); err != nil {
			return nil, err
		}

		return removeRes{}, nil
	}
}
