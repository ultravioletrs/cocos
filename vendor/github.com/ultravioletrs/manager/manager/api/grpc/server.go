package grpc

import (
	"context"

	kitgrpc "github.com/go-kit/kit/transport/grpc"
	"github.com/ultravioletrs/manager/manager"
)

type grpcServer struct {
	run kitgrpc.Handler
	manager.UnimplementedManagerServiceServer
}

// NewServer returns new AuthServiceServer instance.
func NewServer(svc manager.Service) manager.ManagerServiceServer {
	return &grpcServer{
		run: kitgrpc.NewServer(
			runEndpoint(svc),
			decodeRunRequest,
			encodeRunResponse,
		),
	}
}

func decodeRunRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*manager.RunRequest)
	return runReq{
		Computation: req.GetComputation(),
	}, nil
}

func encodeRunResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(runRes)
	return &manager.RunResponse{
		ID: res.ID,
	}, nil
}

func (s *grpcServer) Run(ctx context.Context, req *manager.RunRequest) (*manager.RunResponse, error) {
	_, res, err := s.run.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rr := res.(*manager.RunResponse)
	return rr, nil
}
