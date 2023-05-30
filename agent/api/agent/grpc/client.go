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
		timeout: timeout,
	}
}

// encodeRunRequest is a transport/grpc.EncodeRequestFunc that
// converts a user-domain runReq to a gRPC request.
func encodeRunRequest(_ context.Context, request interface{}) (interface{}, error) {
	req, ok := request.(runReq)
	if !ok {
		return nil, fmt.Errorf("invalid request type: %T", request)
	}

	return &req, nil
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

func (client grpcClient) Run(ctx context.Context, request *agent.RunRequest, _ ...grpc.CallOption) (*agent.RunResponse, error) {
	ctx, close := context.WithTimeout(ctx, client.timeout)
	defer close()

	res, err := client.run(ctx, request)
	if err != nil {
		return nil, err
	}

	runRes := res.(runRes)
	return &agent.RunResponse{Computation: runRes.Computation}, nil
}
