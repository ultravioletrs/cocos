// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/pkg/attestation"
)

func algoEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(algoReq)

		if err := req.validate(); err != nil {
			return algoRes{}, err
		}

		algo := agent.Algorithm{Algorithm: req.Algorithm, Requirements: req.Requirements}

		err := svc.Algo(ctx, algo)
		if err != nil {
			return algoRes{}, err
		}

		return algoRes{}, nil
	}
}

func dataEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(dataReq)

		if err := req.validate(); err != nil {
			return dataRes{}, err
		}

		dataset := agent.Dataset{Dataset: req.Dataset, Filename: req.Filename}

		err := svc.Data(ctx, dataset)
		if err != nil {
			return dataRes{}, err
		}

		return dataRes{}, nil
	}
}

func resultEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(resultReq)

		if err := req.validate(); err != nil {
			return resultRes{}, err
		}
		file, err := svc.Result(ctx)
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
		file, err := svc.Attestation(ctx, req.TeeNonce, req.VtpmNonce, attestation.PlatformType(req.AttType))
		if err != nil {
			return attestationRes{}, err
		}

		return attestationRes{File: file}, nil
	}
}

func imaMeasurementsEndpoint(svc agent.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(imaMeasurementsReq)

		if err := req.validate(); err != nil {
			return imaMeasurementsRes{}, err
		}
		file, pcr10, err := svc.IMAMeasurements(ctx)
		if err != nil {
			return imaMeasurementsRes{}, err
		}

		return imaMeasurementsRes{File: file, PCR10: pcr10}, nil
	}
}
