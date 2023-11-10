// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"

	"github.com/go-kit/kit/transport/grpc"
	"github.com/ultravioletrs/cocos-ai/agent"
)

type grpcServer struct {
	run         grpc.Handler
	algo        grpc.Handler
	data        grpc.Handler
	result      grpc.Handler
	attestation grpc.Handler
	agent.UnimplementedAgentServiceServer
}

// NewServer returns new AgentServiceServer instance.
func NewServer(svc agent.Service) agent.AgentServiceServer {
	return &grpcServer{
		run: grpc.NewServer(
			runEndpoint(svc),
			decodeRunRequest,
			encodeRunResponse,
		),
		algo: grpc.NewServer(
			algoEndpoint(svc),
			decodeAlgoRequest,
			encodeAlgoResponse,
		),
		data: grpc.NewServer(
			dataEndpoint(svc),
			decodeDataRequest,
			encodeDataResponse,
		),
		result: grpc.NewServer(
			resultEndpoint(svc),
			decodeResultRequest,
			encodeResultResponse,
		),
		attestation: grpc.NewServer(
			attestationEndpoint(svc),
			decodeAttestationRequest,
			encodeAttestationResponse,
		),
	}
}

func decodeRunRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*agent.RunRequest)

	return runReq{
		Computation: req.Computation,
	}, nil
}

func encodeRunResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(runRes)
	return &agent.RunResponse{
		Computation: res.Computation,
	}, nil
}

func decodeAlgoRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*agent.AlgoRequest)

	return algoReq{
		Algorithm: req.Algorithm,
		Provider:  req.Provider,
		Id:        req.Id,
	}, nil
}

func encodeAlgoResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(algoRes)
	return &agent.AlgoResponse{
		AlgorithmID: res.AlgorithmID,
	}, nil
}

func decodeDataRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*agent.DataRequest)

	return dataReq{
		Dataset:  req.Dataset,
		Provider: req.Provider,
		Id:       req.Id,
	}, nil
}

func encodeDataResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(dataRes)
	return &agent.DataResponse{
		DatasetID: res.DatasetID,
	}, nil
}

func decodeResultRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*agent.ResultRequest)
	return resultReq{Consumer: req.Consumer}, nil
}

func encodeResultResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(resultRes)
	return &agent.ResultResponse{
		File: res.File,
	}, nil
}

func decodeAttestationRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	// No fields to extract from gRPC request, so returning an empty struct
	return attestationReq{}, nil
}

func encodeAttestationResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(attestationRes)
	return &agent.AttestationResponse{
		File: res.File,
	}, nil
}

func (s *grpcServer) Run(ctx context.Context, req *agent.RunRequest) (*agent.RunResponse, error) {
	_, res, err := s.run.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rr := res.(*agent.RunResponse)
	return rr, nil
}

func (s *grpcServer) Algo(ctx context.Context, req *agent.AlgoRequest) (*agent.AlgoResponse, error) {
	_, res, err := s.algo.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	ar := res.(*agent.AlgoResponse)
	return ar, nil
}

func (s *grpcServer) Data(ctx context.Context, req *agent.DataRequest) (*agent.DataResponse, error) {
	_, res, err := s.data.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	dr := res.(*agent.DataResponse)
	return dr, nil
}

func (s *grpcServer) Result(ctx context.Context, req *agent.ResultRequest) (*agent.ResultResponse, error) {
	_, res, err := s.result.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rr := res.(*agent.ResultResponse)
	return rr, nil
}

func (s *grpcServer) Attestation(ctx context.Context, req *agent.AttestationRequest) (*agent.AttestationResponse, error) {
	_, res, err := s.attestation.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rr := res.(*agent.AttestationResponse)
	return rr, nil
}
