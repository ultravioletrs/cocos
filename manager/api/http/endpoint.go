// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package http

import (
	"context"
	"time"

	"github.com/go-kit/kit/endpoint"
	"github.com/ultravioletrs/cocos/manager"
	"github.com/ultravioletrs/cocos/pkg/clients/grpc"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func runEndpoint(svc manager.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req := request.(runReq)

		if err := req.validate(); err != nil {
			return nil, err
		}

		agentConf := grpc.Config{
			ClientTLS: req.ClientTLS,
			CACerts:   req.CACerts,
			Timeout:   req.Timeout.Duration,
		}
		if agentConf.Timeout == 0 {
			agentConf.Timeout = 60 * time.Second
		}

		computation := manager.Computation{
			Id:              req.Computation.ID,
			Name:            req.Computation.Name,
			Description:     req.Computation.Description,
			Status:          req.Computation.Status,
			Owner:           req.Computation.Owner,
			StartTime:       timestamppb.New(req.Computation.StartTime),
			EndTime:         timestamppb.New(req.Computation.EndTime),
			ResultConsumers: req.Computation.ResultConsumers,
			Ttl:             req.Computation.Ttl,
			Timeout:         req.Computation.Timeout.String(),
		}
		for _, algos := range req.Computation.Algorithms {
			computation.Algorithms = append(computation.Algorithms, &manager.Algorithm{Id: algos.ID, Provider: algos.Provider})
		}
		for _, data := range req.Computation.Datasets {
			computation.Datasets = append(computation.Datasets, &manager.Dataset{Id: data.ID, Provider: data.Provider})
		}
		computation.Metadata = &manager.Metadata{}
		computation.Metadata.Fields = make(map[string]*structpb.Value)
		for k, v := range req.Computation.Metadata {
			val, err := structpb.NewValue(v)
			if err != nil {
				return nil, err
			}
			computation.Metadata.Fields[k] = val
		}
		// Call the Run method on the service
		runID, err := svc.Run(ctx, &computation, agentConf)
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
