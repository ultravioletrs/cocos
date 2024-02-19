// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"
	"fmt"
	"time"

	"github.com/go-kit/kit/endpoint"
	kitgrpc "github.com/go-kit/kit/transport/grpc"
	"github.com/ultravioletrs/cocos/agent"
	"google.golang.org/grpc"
)

const svcName = "agent.AgentService"

type grpcClient struct {
	algo        endpoint.Endpoint
	data        endpoint.Endpoint
	result      endpoint.Endpoint
	attestation endpoint.Endpoint
	timeout     time.Duration
}

// NewClient returns new gRPC client instance.
func NewClient(conn *grpc.ClientConn, timeout time.Duration) agent.AgentServiceClient {
	return &grpcClient{
		algo: kitgrpc.NewClient(
			conn,
			svcName,
			"Algo",
			encodeAlgoRequest,
			decodeAlgoResponse,
			agent.AlgoResponse{},
		).Endpoint(),
		data: kitgrpc.NewClient(
			conn,
			svcName,
			"Data",
			encodeDataRequest,
			decodeDataResponse,
			agent.DataResponse{},
		).Endpoint(),
		result: kitgrpc.NewClient(
			conn,
			svcName,
			"Result",
			encodeResultRequest,
			decodeResultResponse,
			agent.ResultResponse{},
		).Endpoint(),
		attestation: kitgrpc.NewClient(
			conn,
			svcName,
			"Attestation",
			encodeAttestationRequest,
			decodeAttestationResponse,
			agent.AttestationResponse{},
		).Endpoint(),
		timeout: timeout,
	}
}

// encodeAlgoRequest is a transport/grpc.EncodeRequestFunc that
// converts a user-domain algoReq to a gRPC request.
func encodeAlgoRequest(_ context.Context, request interface{}) (interface{}, error) {
	req, ok := request.(*algoReq)
	if !ok {
		return nil, fmt.Errorf("invalid request type: %T", request)
	}

	return &agent.AlgoRequest{
		Algorithm: req.Algorithm,
		Provider:  req.Provider,
		Id:        req.Id,
	}, nil
}

// decodeAlgoResponse is a transport/grpc.DecodeResponseFunc that
// converts a gRPC AlgoResponse to a user-domain response.
func decodeAlgoResponse(_ context.Context, grpcResponse interface{}) (interface{}, error) {
	_, ok := grpcResponse.(*agent.AlgoResponse)
	if !ok {
		return nil, fmt.Errorf("invalid response type: %T", grpcResponse)
	}

	return algoRes{}, nil
}

// encodeDataRequest is a transport/grpc.EncodeRequestFunc that
// converts a user-domain dataReq to a gRPC request.
func encodeDataRequest(_ context.Context, request interface{}) (interface{}, error) {
	req, ok := request.(*dataReq)
	if !ok {
		return nil, fmt.Errorf("invalid request type: %T", request)
	}

	return &agent.DataRequest{
		Dataset:  req.Dataset,
		Provider: req.Provider,
		Id:       req.Id,
	}, nil
}

// decodeDataResponse is a transport/grpc.DecodeResponseFunc that
// converts a gRPC DataResponse to a user-domain response.
func decodeDataResponse(_ context.Context, grpcResponse interface{}) (interface{}, error) {
	_, ok := grpcResponse.(*agent.DataResponse)
	if !ok {
		return nil, fmt.Errorf("invalid response type: %T", grpcResponse)
	}

	return dataRes{}, nil
}

// encodeResultRequest is a transport/grpc.EncodeRequestFunc that
// converts a user-domain resultReq to a gRPC request.
func encodeResultRequest(_ context.Context, request interface{}) (interface{}, error) {
	req, ok := request.(*resultReq)
	if !ok {
		return nil, fmt.Errorf("invalid request type: %T", request)
	}

	return &agent.ResultRequest{
		Consumer: req.Consumer,
	}, nil
}

// decodeResultResponse is a transport/grpc.DecodeResponseFunc that
// converts a gRPC ResultResponse to a user-domain response.
func decodeResultResponse(_ context.Context, grpcResponse interface{}) (interface{}, error) {
	response, ok := grpcResponse.(*agent.ResultResponse)
	if !ok {
		return nil, fmt.Errorf("invalid response type: %T", grpcResponse)
	}

	return resultRes{
		File: response.File,
	}, nil
}

// encodeAttestationRequest is a transport/grpc.EncodeRequestFunc that
// converts a user-domain attestationReq to a gRPC request.
func encodeAttestationRequest(_ context.Context, request interface{}) (interface{}, error) {
	req, ok := request.(*attestationReq)
	if !ok {
		return nil, fmt.Errorf("invalid request type: %T", request)
	}
	return &agent.AttestationRequest{ReportData: req.ReportData}, nil
}

// decodeAttestationResponse is a transport/grpc.DecodeResponseFunc that
// converts a gRPC AttestationResponse to a user-domain response.
func decodeAttestationResponse(_ context.Context, grpcResponse interface{}) (interface{}, error) {
	response, ok := grpcResponse.(*agent.AttestationResponse)
	if !ok {
		return nil, fmt.Errorf("invalid response type: %T", grpcResponse)
	}

	return attestationRes{
		File: response.File,
	}, nil
}

// Algo implements the Algo method of the agent.AgentServiceClient interface.
func (c grpcClient) Algo(ctx context.Context, request *agent.AlgoRequest, _ ...grpc.CallOption) (*agent.AlgoResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	_, err := c.algo(ctx, &algoReq{Algorithm: request.Algorithm, Provider: request.Provider, Id: request.Id})
	if err != nil {
		return nil, err
	}

	return &agent.AlgoResponse{}, nil
}

// Data implements the Data method of the agent.AgentServiceClient interface.
func (c grpcClient) Data(ctx context.Context, request *agent.DataRequest, _ ...grpc.CallOption) (*agent.DataResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	_, err := c.data(ctx, &dataReq{Dataset: request.Dataset, Provider: request.Provider, Id: request.Id})
	if err != nil {
		return nil, err
	}

	return &agent.DataResponse{}, nil
}

// Result implements the Result method of the agent.AgentServiceClient interface.
func (c grpcClient) Result(ctx context.Context, request *agent.ResultRequest, _ ...grpc.CallOption) (*agent.ResultResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	res, err := c.result(ctx, &resultReq{Consumer: request.Consumer})
	if err != nil {
		return nil, err
	}

	resultRes := res.(resultRes)
	return &agent.ResultResponse{File: resultRes.File}, nil
}

// Result implements the Result method of the agent.AgentServiceClient interface.
func (c grpcClient) Attestation(ctx context.Context, request *agent.AttestationRequest, _ ...grpc.CallOption) (*agent.AttestationResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	res, err := c.attestation(ctx, &attestationReq{ReportData: request.ReportData})
	if err != nil {
		return nil, err
	}

	attestationRes := res.(attestationRes)
	return &agent.AttestationResponse{File: attestationRes.File}, nil
}
