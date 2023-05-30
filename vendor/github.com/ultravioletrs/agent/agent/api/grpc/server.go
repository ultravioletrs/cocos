package grpc

import (
	"context"
	"encoding/json"

	kitot "github.com/go-kit/kit/tracing/opentracing"
	kitgrpc "github.com/go-kit/kit/transport/grpc"
	"github.com/opentracing/opentracing-go"
	"github.com/ultravioletrs/agent/agent"
)

type grpcServer struct {
	run kitgrpc.Handler
	agent.UnimplementedAgentServiceServer
}

// NewServer returns new AuthServiceServer instance.
func NewServer(tracer opentracing.Tracer, svc agent.Service) agent.AgentServiceServer {
	return &grpcServer{
		run: kitgrpc.NewServer(
			kitot.TraceServer(tracer, "run")(runEndpoint(svc)),
			decodeRunRequest,
			encodeRunResponse,
		),
	}
}

func decodeRunRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*agent.RunRequest)

	var computation agent.Computation
	err := json.Unmarshal(req.Computation, &computation)
	if err != nil {
		return nil, err
	}

	return runReq{
		computation: computation,
	}, nil
}

func encodeRunResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(runRes)
	return &agent.RunResponse{
		Computation: res.Computation,
	}, nil
}

func (s *grpcServer) Run(ctx context.Context, req *agent.RunRequest) (*agent.RunResponse, error) {
	_, res, err := s.run.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rr := res.(*agent.RunResponse)
	return rr, nil
}
