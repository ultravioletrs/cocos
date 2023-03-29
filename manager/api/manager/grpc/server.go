package grpc

import (
	"context"

	kitot "github.com/go-kit/kit/tracing/opentracing"
	kitgrpc "github.com/go-kit/kit/transport/grpc"
	"github.com/opentracing/opentracing-go"
	"github.com/ultravioletrs/manager/manager"
)

type grpcServer struct {
	createDomain kitgrpc.Handler
	manager.UnimplementedManagerServiceServer
}

// NewServer returns new AuthServiceServer instance.
func NewServer(tracer opentracing.Tracer, svc manager.Service) manager.ManagerServiceServer {
	return &grpcServer{
		createDomain: kitgrpc.NewServer(
			kitot.TraceServer(tracer, "createDomain")(createDomainEndpoint(svc)),
			decodeCreateDomainRequest,
			encodeCreateDomainResponse,
		),
	}
}

func decodeCreateDomainRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*manager.CreateDomainRequest)
	return createDomainReq{Pool: req.GetPool(), Volume: req.GetVolume(), Domain: req.GetDomain()}, nil
}

func encodeCreateDomainResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(createDomainRes)
	return manager.CreateDomainResponse{Name: res.Name}, nil
}

func (s *grpcServer) CreateDomain(ctx context.Context, req *manager.CreateDomainRequest) (*manager.CreateDomainResponse, error) {
	_, res, err := s.createDomain.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	cdr := res.(manager.CreateDomainResponse)
	return &cdr, nil
}
