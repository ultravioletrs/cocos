package grpc

import (
	"context"
	"fmt"
	"time"

	"github.com/go-kit/kit/endpoint"
	kitgrpc "github.com/go-kit/kit/transport/grpc"
	"github.com/ultravioletrs/manager/manager"
	"google.golang.org/grpc"
)

const svcName = "manager.ManagerService"

type grpcClient struct {
	run     endpoint.Endpoint
	timeout time.Duration
}

// NewClient returns new gRPC client instance.
func NewClient(conn *grpc.ClientConn, timeout time.Duration) manager.ManagerServiceClient {
	return &grpcClient{
		run: kitgrpc.NewClient(
			conn,
			svcName,
			"Run",
			encodeRunRequest,
			decodeRunResponse,
			manager.RunResponse{},
		).Endpoint(),
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
	return &manager.RunRequest{
		Computation: req.Computation,
	}, nil
}

// decodeRunResponse is a transport/grpc.DecodeResponseFunc that
// converts a gRPC RunResponse to a user-domain response.
func decodeRunResponse(_ context.Context, grpcResponse interface{}) (interface{}, error) {
	response, ok := grpcResponse.(*manager.RunResponse)
	if !ok {
		return nil, fmt.Errorf("invalid response type: %T", grpcResponse)
	}
	return runRes{
		ID: response.ID,
	}, nil
}

func (client grpcClient) Run(ctx context.Context, req *manager.RunRequest, _ ...grpc.CallOption) (*manager.RunResponse, error) {
	ctx, close := context.WithTimeout(ctx, client.timeout)
	defer close()

	runReq := runReq{
		Computation: req.GetComputation(),
	}

	res, err := client.run(ctx, runReq)
	if err != nil {
		return nil, err
	}

	runRes := res.(runRes)
	return &manager.RunResponse{ID: runRes.ID}, nil
}
