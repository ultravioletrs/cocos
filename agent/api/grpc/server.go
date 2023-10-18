package grpc

import (
	"context"

	kitgrpc "github.com/go-kit/kit/transport/grpc"
	"github.com/ultravioletrs/agent/agent"
)

type grpcServer struct {
	run    kitgrpc.Handler
	algo   kitgrpc.Handler
	data   kitgrpc.Handler
	result kitgrpc.Handler
	agent.UnimplementedAgentServiceServer
}

// NewServer returns new AgentServiceServer instance.
func NewServer(svc agent.Service) agent.AgentServiceServer {
	return &grpcServer{
		run: kitgrpc.NewServer(
			runEndpoint(svc),
			decodeRunRequest,
			encodeRunResponse,
		),
		algo: kitgrpc.NewServer(
			algoEndpoint(svc),
			decodeAlgoRequest,
			encodeAlgoResponse,
		),
		data: kitgrpc.NewServer(
			dataEndpoint(svc),
			decodeDataRequest,
			encodeDataResponse,
		),
		result: kitgrpc.NewServer(
			resultEndpoint(svc),
			decodeResultRequest,
			encodeResultResponse,
		),
	}
}

func decodeRunRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*agent.RunRequest)

	return runReq{
		Computation: req.Computation,
	}, nil
}

func encodeRunResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(runRes)
	return &agent.RunResponse{
		Computation: res.Computation,
	}, nil
}

func decodeAlgoRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*agent.AlgoRequest)

	return algoReq{
		Algorithm: req.Algorithm,
	}, nil
}

func encodeAlgoResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(algoRes)
	return &agent.AlgoResponse{
		AlgorithmID: res.AlgorithmID,
	}, nil
}

func decodeDataRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(*agent.DataRequest)

	return dataReq{
		Dataset: req.Dataset,
	}, nil
}

func encodeDataResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(dataRes)
	return &agent.DataResponse{
		DatasetID: res.DatasetID,
	}, nil
}

func decodeResultRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	// No fields to extract from gRPC request, so returning an empty struct
	return resultReq{}, nil
}

func encodeResultResponse(_ context.Context, response interface{}) (interface{}, error) {
	res := response.(resultRes)
	return &agent.ResultResponse{
		File: res.File,
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

func (s *grpcServer) Algo(ctx context.Context, req *agent.AlgoRequest) (*agent.AlgoResponse, error) {
	_, res, err := s.algo.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	ar := res.(*agent.AlgoResponse)
	return ar, nil
}

func (s *grpcServer) Data(ctx context.Context, req *agent.DataRequest) (*agent.DataResponse, error) {
	_, res, err := s.data.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	dr := res.(*agent.DataResponse)
	return dr, nil
}

func (s *grpcServer) Result(ctx context.Context, req *agent.ResultRequest) (*agent.ResultResponse, error) {
	_, res, err := s.result.ServeGRPC(ctx, req)
	if err != nil {
		return nil, err
	}
	rr := res.(*agent.ResultResponse)
	return rr, nil
}
