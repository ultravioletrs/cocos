package api

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/ultravioletrs/cocos/computations"
)

func createComputation(svc computations.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(createReq)
		if err := req.validate(); err != nil {
			return createRes{}, err
		}
		uid, err := svc.CreateComputation(ctx, req.token, req.computation)
		if err != nil {
			return createRes{}, err
		}
		ucr := createRes{
			ID:      uid,
			created: true,
		}

		return ucr, nil
	}
}
