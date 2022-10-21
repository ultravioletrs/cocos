package api

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/ultravioletrs/cocos/datasets"
)

func createDatasetsEndpoint(svc datasets.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(createReq)

		id, err := svc.CreateDataset(ctx, req.dataset)
		if err != nil {
			return createRes{}, err
		}

		res := createRes{
			ID:      id,
			created: true,
		}

		return res, nil
	}
}

func viewDatasetsEndpoint(svc datasets.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(viewRequest)

		ds, err := svc.ViewDataset(ctx, req.owner, req.id)
		if err != nil {
			return nil, err
		}
		res := viewRes{
			Dataset: ds,
		}
		return res, nil
	}
}

func listDatasetsEndpoint(svc datasets.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(listResourcesReq)

		page, err := svc.ListDatasets(ctx, req.owner, req.pageMetadata)
		if err != nil {
			return nil, err
		}

		res := datasetsPageRes{
			pageRes: pageRes{
				Total:  page.Total,
				Offset: page.Offset,
				Limit:  page.Limit,
				Order:  page.Order,
				Dir:    page.Dir,
			},
			Datasets: []datasets.Dataset{},
		}
		res.Datasets = append(res.Datasets, page.Datasets...)

		return res, nil
	}
}

func updateDatasetEndpoint(svc datasets.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(updateReq)

		dataset := datasets.Dataset{
			ID:          req.id,
			Name:        req.Name,
			Description: req.Description,
			Metadata:    req.Metadata,
		}

		if err := svc.UpdateDataset(ctx, dataset); err != nil {
			return nil, err
		}

		res := createRes{ID: req.id, created: false}
		return res, nil
	}
}

func uploadDatasetEndpoint(svc datasets.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(uploadReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		if err := svc.UploadDataset(ctx, req.id, req.owner, req.Payload); err != nil {
			return nil, err
		}

		res := createRes{ID: req.id, created: false}
		return res, nil
	}
}

func removeDatasetEndpoint(svc datasets.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(viewRequest)

		if err := svc.RemoveDataset(ctx, req.id); err != nil {
			return nil, err
		}

		return removeRes{}, nil
	}
}
