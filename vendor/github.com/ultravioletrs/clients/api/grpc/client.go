package grpc

import (
	"context"
	"time"

	"github.com/go-kit/kit/endpoint"
	kitot "github.com/go-kit/kit/tracing/opentracing"
	kitgrpc "github.com/go-kit/kit/transport/grpc"
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/ultravioletrs/clients"
	"google.golang.org/grpc"
)

const svcName = "clients.AuthService"

var _ clients.AuthServiceClient = (*grpcClient)(nil)

type grpcClient struct {
	authorize endpoint.Endpoint
	timeout   time.Duration
}

// NewClient returns new gRPC client instance.
func NewClient(tracer opentracing.Tracer, conn *grpc.ClientConn, timeout time.Duration) clients.AuthServiceClient {
	return &grpcClient{
		authorize: kitot.TraceClient(tracer, "authorize")(kitgrpc.NewClient(
			conn,
			svcName,
			"Authorize",
			encodeAuthorizeRequest,
			decodeAuthorizeResponse,
			clients.AuthorizeRes{},
		).Endpoint()),

		timeout: timeout,
	}
}

func (client grpcClient) Authorize(ctx context.Context, req *clients.AuthorizeReq, _ ...grpc.CallOption) (r *clients.AuthorizeRes, err error) {
	ctx, close := context.WithTimeout(ctx, client.timeout)
	defer close()

	res, err := client.authorize(ctx, authReq{Act: req.GetAct(), Obj: req.GetObj(), Sub: req.GetSub()})
	if err != nil {
		return &clients.AuthorizeRes{}, err
	}

	ar := res.(authorizeRes)
	return &clients.AuthorizeRes{Authorized: ar.authorized}, err
}

func decodeAuthorizeResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(*clients.AuthorizeRes)
	return authorizeRes{authorized: res.Authorized}, nil
}

func encodeAuthorizeRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(authReq)
	return &clients.AuthorizeReq{
		Sub: req.Sub,
		Obj: req.Obj,
		Act: req.Act,
	}, nil
}
