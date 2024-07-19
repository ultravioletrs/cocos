// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"github.com/go-kit/kit/transport/grpc"
	"github.com/ultravioletrs/cocos/agent"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var _ agent.AgentServiceServer = (*grpcServer)(nil)

type grpcServer struct {
	algo        grpc.Handler
	data        grpc.Handler
	result      grpc.Handler
	attestation grpc.Handler
	logger      *slog.Logger
	agent.UnimplementedAgentServiceServer
}

// NewServer returns new AgentServiceServer instance.
func NewServer(svc agent.Service, logger *slog.Logger) agent.AgentServiceServer {
	return &grpcServer{
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
		logger: logger,
	}
}

func decodeAlgoRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*agent.AlgoRequest)

	return algoReq{
		Algorithm: req.Algorithm,
	}, nil
}

func encodeAlgoResponse(_ context.Context, response interface{}) (interface{}, error) {
	return &agent.AlgoResponse{}, nil
}

func decodeDataRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*agent.DataRequest)

	return dataReq{
		Dataset: req.Dataset,
	}, nil
}

func encodeDataResponse(_ context.Context, response interface{}) (interface{}, error) {
	return &agent.DataResponse{}, nil
}

func decodeResultRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	return resultReq{}, nil
}

func encodeResultResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(resultRes)
	return &agent.ResultResponse{
		File: res.File,
	}, nil
}

func decodeAttestationRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*agent.AttestationRequest)
	if len(req.ReportData) != agent.ReportDataSize {
		return nil, errors.New("malformed report data, expect 64 bytes")
	}
	return attestationReq{ReportData: [agent.ReportDataSize]byte(req.ReportData)}, nil
}

func encodeAttestationResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(attestationRes)
	return &agent.AttestationResponse{
		File: res.File,
	}, nil
}

// Algo implements agent.AgentServiceServer.
func (s *grpcServer) Algo(stream agent.AgentService_AlgoServer) error {
	var algoFile, reqFile []byte
	for {
		algoChunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return status.Error(codes.Internal, err.Error())
		}
		algoFile = append(algoFile, algoChunk.Algorithm...)
		reqFile = append(reqFile, algoChunk.Requirements...)
	}
	s.logger.Info("algo req" + string(reqFile))
	_, res, err := s.algo.ServeGRPC(stream.Context(), &agent.AlgoRequest{Algorithm: algoFile, Requirements: reqFile})
	if err != nil {
		return err
	}
	ar := res.(*agent.AlgoResponse)
	return stream.SendAndClose(ar)
}

// Data implements agent.AgentServiceServer.
func (s *grpcServer) Data(stream agent.AgentService_DataServer) error {
	var dataFile []byte
	for {
		dataChunk, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return status.Error(codes.Internal, err.Error())
		}
		dataFile = append(dataFile, dataChunk.Dataset...)
	}
	_, res, err := s.data.ServeGRPC(stream.Context(), &agent.DataRequest{Dataset: dataFile})
	if err != nil {
		return err
	}
	ar := res.(*agent.DataResponse)
	return stream.SendAndClose(ar)
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
