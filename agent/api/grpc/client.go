package grpc

import (
	"context"
	"fmt"
	"time"

	"github.com/go-kit/kit/endpoint"
	kitot "github.com/go-kit/kit/tracing/opentracing"
	kitgrpc "github.com/go-kit/kit/transport/grpc"
	"github.com/opentracing/opentracing-go"
	"github.com/ultravioletrs/agent/agent"
	"google.golang.org/grpc"
)

const (
	svcName = "agent_proto.AgentService"
)

type grpcClient struct {
	run     endpoint.Endpoint
	algo    endpoint.Endpoint
	data    endpoint.Endpoint
	timeout time.Duration
}

// NewClient returns new gRPC client instance.
func NewClient(tracer opentracing.Tracer, conn *grpc.ClientConn, timeout time.Duration) agent.AgentServiceClient {
	return &grpcClient{
		run: kitot.TraceClient(tracer, "run")(kitgrpc.NewClient(
			conn,
			svcName,
			"Run",
			encodeRunRequest,
			decodeRunResponse,
			agent.RunResponse{},
		).Endpoint()),
		algo: kitot.TraceClient(tracer, "algo")(kitgrpc.NewClient(
			conn,
			svcName,
			"Algo",
			encodeAlgoRequest,
			decodeAlgoResponse,
			agent.AlgoResponse{},
		).Endpoint()),
		data: kitot.TraceClient(tracer, "data")(kitgrpc.NewClient(
			conn,
			svcName,
			"Data",
			encodeDataRequest,
			decodeDataResponse,
			agent.DataResponse{},
		).Endpoint()),
		timeout: timeout,
	}
}

// encodeRunRequest is a transport/grpc.EncodeRequestFunc that
// converts a user-domain runReq to a gRPC request.
func encodeRunRequest(_ context.Context, request interface{}) (interface{}, error) {
	req, ok := request.(*runReq)
	if !ok {
		return nil, fmt.Errorf("invalid request type: %T", request)
	}

	return &agent.RunRequest{
		Computation: req.Computation,
	}, nil
}

// decodeRunResponse is a transport/grpc.DecodeResponseFunc that
// converts a gRPC RunResponse to a user-domain response.
func decodeRunResponse(_ context.Context, grpcResponse interface{}) (interface{}, error) {
	response, ok := grpcResponse.(*agent.RunResponse)
	if !ok {
		return nil, fmt.Errorf("invalid response type: %T", grpcResponse)
	}
	return runRes{
		Computation: response.Computation,
	}, nil
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
	}, nil
}

// decodeAlgoResponse is a transport/grpc.DecodeResponseFunc that
// converts a gRPC AlgoResponse to a user-domain response.
func decodeAlgoResponse(_ context.Context, grpcResponse interface{}) (interface{}, error) {
	response, ok := grpcResponse.(*agent.AlgoResponse)
	if !ok {
		return nil, fmt.Errorf("invalid response type: %T", grpcResponse)
	}

	return algoRes{
		AlgorithmID: response.AlgorithmID,
	}, nil
}

// encodeDataRequest is a transport/grpc.EncodeRequestFunc that
// converts a user-domain dataReq to a gRPC request.
func encodeDataRequest(_ context.Context, request interface{}) (interface{}, error) {
	req, ok := request.(*dataReq)
	if !ok {
		return nil, fmt.Errorf("invalid request type: %T", request)
	}

	return &agent.DataRequest{
		Dataset: req.Dataset,
	}, nil
}

// decodeDataResponse is a transport/grpc.DecodeResponseFunc that
// converts a gRPC DataResponse to a user-domain response.
func decodeDataResponse(_ context.Context, grpcResponse interface{}) (interface{}, error) {
	response, ok := grpcResponse.(*agent.DataResponse)
	if !ok {
		return nil, fmt.Errorf("invalid response type: %T", grpcResponse)
	}

	return dataRes{
		DatasetID: response.DatasetID,
	}, nil
}

// Run implements the Run method of the agent.AgentServiceClient interface.
func (client grpcClient) Run(ctx context.Context, request *agent.RunRequest, _ ...grpc.CallOption) (*agent.RunResponse, error) {
	ctx, close := context.WithTimeout(ctx, client.timeout)
	defer close()

	res, err := client.run(ctx, &runReq{Computation: request.Computation})
	if err != nil {
		return nil, err
	}

	runRes := res.(runRes)
	return &agent.RunResponse{Computation: runRes.Computation}, nil
}

// Algo implements the Algo method of the agent.AgentServiceClient interface.
func (client grpcClient) Algo(ctx context.Context, request *agent.AlgoRequest, _ ...grpc.CallOption) (*agent.AlgoResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.algo(ctx, &algoReq{Algorithm: request.Algorithm})
	if err != nil {
		return nil, err
	}

	algoRes := res.(algoRes)
	return &agent.AlgoResponse{AlgorithmID: algoRes.AlgorithmID}, nil
}

// Data implements the Data method of the agent.AgentServiceClient interface.
func (client grpcClient) Data(ctx context.Context, request *agent.DataRequest, _ ...grpc.CallOption) (*agent.DataResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.data(ctx, &dataReq{Dataset: request.Dataset})
	if err != nil {
		return nil, err
	}

	dataRes := res.(dataRes)
	return &agent.DataResponse{DatasetID: dataRes.DatasetID}, nil
}
