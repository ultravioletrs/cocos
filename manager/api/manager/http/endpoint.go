// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/ultravioletrs/manager/manager"
)

func pingEndpoint(svc manager.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(pingReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		greeting, err := svc.Ping(req.Secret)
		if err != nil {
			return nil, err
		}

		res := pingRes{
			Greeting: greeting,
		}
		return res, nil
	}
}

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
