package grpc

import (
	"context"
	"fmt"
	"time"

	"github.com/go-kit/kit/endpoint"
	kitot "github.com/go-kit/kit/tracing/opentracing"
	kitgrpc "github.com/go-kit/kit/transport/grpc"
	"github.com/opentracing/opentracing-go"
	"github.com/ultravioletrs/manager/manager"
	"google.golang.org/grpc"
)

const (
	svcName = "manager.ManagerService"
)

type grpcClient struct {
	createDomain endpoint.Endpoint
	timeout      time.Duration
}

// NewClient returns new gRPC client instance.
func NewClient(tracer opentracing.Tracer, conn *grpc.ClientConn, timeout time.Duration) manager.ManagerServiceClient {
	return &grpcClient{
		createDomain: kitot.TraceClient(tracer, "createDomain")(kitgrpc.NewClient(
			conn,
			svcName,
			"CreateDomain",
			encodeCreateDomainRequest,
			decodeCreateDomainResponse,
			nil,
		).Endpoint()),

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
