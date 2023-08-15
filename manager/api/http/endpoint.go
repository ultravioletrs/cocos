// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"
	"strings"

	"github.com/go-kit/kit/endpoint"
	"github.com/ultravioletrs/manager/manager"
)

func createLibvirtDomainEndpoint(svc manager.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(createLibvirtDomainReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		name, err := svc.CreateLibvirtDomain(ctx, req.Pool, req.Volume, req.Domain)
		if err != nil {
			return nil, err
		}

		res := createLibvirtDomainRes{
			Name: name,
		}

		return res, nil
	}
}

func createQemuVMEndpoint(svc manager.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(createQemuVMReq)

		if err := req.validate(); err != nil {
			return createQemuVMReq{}, err
		}

		cmd, err := svc.CreateQemuVM(ctx)
		if err != nil {
			return createQemuVMRes{}, err
		}

		return createQemuVMRes{
			Path: cmd.Path,
			Args: strings.Join(cmd.Args, " "),
		}, nil
	}
}
func runEndpoint(svc manager.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(runReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		// Call the Run method on the service
		runID, err := svc.Run(ctx, req.Computation)
		if err != nil {
			return nil, err
		}

		// Create the response
		res := runRes{
			ID: runID,
		}

		return res, nil
	}
}
