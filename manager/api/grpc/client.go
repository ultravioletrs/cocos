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

const svcName = "manager_proto.ManagerService"

type grpcClient struct {
	createDomain endpoint.Endpoint
	run          endpoint.Endpoint
	timeout      time.Duration
}

// NewClient returns new gRPC client instance.
func NewClient(conn *grpc.ClientConn, timeout time.Duration) manager.ManagerServiceClient {
	return &grpcClient{
		createDomain: kitgrpc.NewClient(
			conn,
			svcName,
			"CreateDomain",
			encodeCreateDomainRequest,
			decodeCreateDomainResponse,
			manager.CreateDomainResponse{},
		).Endpoint(),
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

func (client grpcClient) CreateDomain(ctx context.Context, req *manager.CreateDomainRequest, _ ...grpc.CallOption) (*manager.CreateDomainResponse, error) {
	ctx, close := context.WithTimeout(ctx, client.timeout)
	defer close()

	res, err := client.createDomain(ctx, createDomainReq{Pool: req.GetPool(),
		Volume: req.GetVolume(), Domain: req.GetDomain()})
	if err != nil {
		return nil, err
	}

	cdr := res.(createDomainRes)

	return &manager.CreateDomainResponse{Name: cdr.Name}, nil
}

// encodeCreateDomainRequest is a transport/grpc.EncodeRequestFunc that
// converts a user-domain CreateDomainRequest to a gRPC request.
func encodeCreateDomainRequest(_ context.Context, request interface{}) (interface{}, error) {
	req, ok := request.(createDomainReq)
	if !ok {
		return nil, fmt.Errorf("invalid request type: %T", request)
	}
	return &manager.CreateDomainRequest{
		Pool:   req.Pool,
		Volume: req.Volume,
		Domain: req.Domain,
	}, nil
}

// decodeCreateDomainResponse is a transport/grpc.DecodeResponseFunc that
// converts a gRPC CreateDomainResponse to a user-domain response.
func decodeCreateDomainResponse(_ context.Context, grpcResponse interface{}) (interface{}, error) {
	response, ok := grpcResponse.(*manager.CreateDomainResponse)
	if !ok {
		return nil, fmt.Errorf("invalid response type: %T", grpcResponse)
	}
	return createDomainRes{
		Name: response.Name,
	}, nil
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
