// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package service

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/ultravioletrs/cocos/agent/algorithm"
	"github.com/ultravioletrs/cocos/agent/algorithm/binary"
	"github.com/ultravioletrs/cocos/agent/algorithm/docker"
	"github.com/ultravioletrs/cocos/agent/algorithm/python"
	"github.com/ultravioletrs/cocos/agent/algorithm/wasm"
	"github.com/ultravioletrs/cocos/agent/events"
	pb "github.com/ultravioletrs/cocos/agent/runner"
	"google.golang.org/protobuf/types/known/emptypb"
)

var _ pb.ComputationRunnerServer = (*RunnerService)(nil)

type RunnerService struct {
	pb.UnimplementedComputationRunnerServer
	logger      *slog.Logger
	eventSvc    events.Service
	currentAlgo algorithm.Algorithm
	mu          sync.Mutex
}

func New(logger *slog.Logger, eventSvc events.Service) *RunnerService {
	return &RunnerService{
		logger:   logger,
		eventSvc: eventSvc,
	}
}

func (s *RunnerService) Run(ctx context.Context, req *pb.RunRequest) (*pb.RunResponse, error) {
	s.mu.Lock()
	if s.currentAlgo != nil {
		s.mu.Unlock()
		return &pb.RunResponse{
			ComputationId: req.ComputationId,
			Error:         "computation already running",
		}, nil
	}
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.currentAlgo = nil
		s.mu.Unlock()
	}()

	if req.AlgorithmPath == "" {
		return nil, fmt.Errorf("algorithm path is required")
	}

	var algo algorithm.Algorithm

	switch req.AlgoType {
	case string(algorithm.AlgoTypeBin):
		algo = binary.NewAlgorithm(s.logger, s.eventSvc, req.AlgorithmPath, req.Args, req.ComputationId)
	case string(algorithm.AlgoTypePython):
		// Assuming default python runtime if not specified in request (proto doesn't have runtime field yet)
		// We can add it or assume.
		runtime := python.PyRuntime
		algo = python.NewAlgorithm(s.logger, s.eventSvc, runtime, req.RequirementsPath, req.AlgorithmPath, req.Args, req.ComputationId)
	case string(algorithm.AlgoTypeWasm):
		algo = wasm.NewAlgorithm(s.logger, s.eventSvc, req.Args, req.AlgorithmPath, req.ComputationId)
	case string(algorithm.AlgoTypeDocker):
		algo = docker.NewAlgorithm(s.logger, s.eventSvc, req.AlgorithmPath, req.ComputationId)
	default:
		return nil, fmt.Errorf("unsupported algorithm type: %s", req.AlgoType)
	}

	s.mu.Lock()
	s.currentAlgo = algo
	s.mu.Unlock()

	if err := algo.Run(); err != nil {
		s.logger.Error("computation failed", "error", err)
		return &pb.RunResponse{
			ComputationId: req.ComputationId,
			Error:         err.Error(),
		}, nil
	}

	return &pb.RunResponse{
		ComputationId: req.ComputationId,
	}, nil
}

func (s *RunnerService) Stop(ctx context.Context, req *pb.StopRequest) (*emptypb.Empty, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.currentAlgo != nil {
		if err := s.currentAlgo.Stop(); err != nil {
			return nil, err
		}
	}
	return &emptypb.Empty{}, nil
}
