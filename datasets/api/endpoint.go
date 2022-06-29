package api

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/ultravioletrs/cocos/datasets"
)

func createDatasetsEndpoint(svc datasets.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(createReq)
		if err := req.validate(); err != nil {
			return createRes{}, err
		}
		uid, err := svc.CreateDataset(ctx, req.token, req.dataset)
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

func viewDatasetsEndpoint(svc datasets.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(viewReq)
		if err := req.validate(); err != nil {
			return viewRes{}, err
		}
		dataset, err := svc.ViewDataset(ctx, req.token, req.id)
		if err != nil {
			return createRes{}, err
		}
		ret := viewRes{
			Dataset: dataset,
		}

		return ret, nil
	}
}

func listDatasetsEndpoint(svc datasets.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listReq)
		if err := req.validate(); err != nil {
			return listRes{}, err
		}
		res, err := svc.ListDatasets(ctx, req.token, req.meta)
		if err != nil {
			return listRes{}, err
		}
		ret := listRes{
			Page: res,
		}
		return ret, nil
	}
}

func updateDatasetsEndpoint(svc datasets.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateReq)
		if err := req.validate(); err != nil {
			return nil, err
		}

		dataset := datasets.Dataset{
			ID:          req.id,
			Name:        req.Name,
			Description: req.Description,
			Metadata:    req.Metadata,
		}

		if err := svc.UpdateDataset(ctx, req.token, dataset); err != nil {
			return nil, err
		}

		res := createRes{ID: req.id, created: false}
		return res, nil
	}
}

func removeDatasetsEndpoint(svc datasets.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(viewReq)

		err := req.validate()
		if err == errors.ErrNotFound {
			return removeRes{}, nil
		}

		if err != nil {
			return nil, err
		}

		if err := svc.RemoveDataset(ctx, req.token, req.id); err != nil {
			return nil, err
		}

		return removeRes{}, nil
	}
}
