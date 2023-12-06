// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"
	"time"

	"github.com/go-kit/kit/transport/grpc"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/ultravioletrs/cocos/manager"
)

type grpcServer struct {
	run    grpc.Handler
	status grpc.Handler
	manager.UnimplementedManagerServiceServer
}

// NewServer returns new AuthServiceServer instance.
func NewServer(svc manager.Service) manager.ManagerServiceServer {
	return &grpcServer{
		run: grpc.NewServer(
			runEndpoint(svc),
			decodeRunRequest,
			encodeRunResponse,
		),
		status: grpc.NewServer(
			statusEndpoint(svc),
			nopDecoder,
			encodeStatusResponse,
		),
	}
}

func decodeRunRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*manager.RunRequest)
	dur, err := time.ParseDuration(req.GetTimeout())
	if err != nil {
		return nil, err
	}
	return runReq{
		Computation: req.GetComputation(),
		ClientTLS:   req.ClientTls,
		CACerts:     req.CaCerts,
		Timeout:     dur,
	}, nil
}

func encodeRunResponse(_ context.Context, response interface{}) (interface{}, error) {
	return &manager.RunResponse{}, nil
}

func encodeStatusResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(statusRes)
	return &manager.StatusResponse{
		Status: res.Status,
	}, nil
}

func (s *grpcServer) Run(ctx context.Context, req *manager.RunRequest) (*manager.RunResponse, error) {
	_, res, err := s.run.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rr := res.(*manager.RunResponse)
	return rr, nil
}

func (s *grpcServer) Status(ctx context.Context, req *empty.Empty) (*manager.StatusResponse, error) {
	_, res, err := s.status.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rr := res.(*manager.StatusResponse)
	return rr, nil
}
