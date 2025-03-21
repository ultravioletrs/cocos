// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"
	"errors"

	"github.com/ultravioletrs/cocos/manager"
	"google.golang.org/protobuf/types/known/emptypb"
)

var (
	_                manager.ManagerServiceServer = (*grpcServer)(nil)
	ErrUnexpectedMsg                              = errors.New("unknown message type")
)

type grpcServer struct {
	manager.UnimplementedManagerServiceServer
	svc manager.Service
}

// NewServer returns new AuthServiceServer instance.
func NewServer(svc manager.Service) manager.ManagerServiceServer {
	return &grpcServer{
		svc: svc,
	}
}

func (s *grpcServer) CreateVm(ctx context.Context, req *manager.CreateReq) (*manager.CreateRes, error) {
	port, id, err := s.svc.CreateVM(ctx, req)
	if err != nil {
		return nil, err
	}

	return &manager.CreateRes{
		ForwardedPort: port,
		CvmId:         id,
	}, nil
}

func (s *grpcServer) RemoveVm(ctx context.Context, req *manager.RemoveReq) (*emptypb.Empty, error) {
	if err := s.svc.RemoveVM(ctx, req.CvmId); err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

func (s *grpcServer) CVMInfo(ctx context.Context, req *manager.CVMInfoReq) (*manager.CVMInfoRes, error) {
	ovmf, cpunum, cputype, eosversion := s.svc.ReturnCVMInfo(ctx)

	return &manager.CVMInfoRes{
		OvmfVersion: ovmf,
		CpuNum:      int32(cpunum),
		CpuType:     cputype,
		EosVersion:  eosversion,
		Id:          req.Id,
	}, nil
}

func (s *grpcServer) AttestationPolicy(ctx context.Context, req *manager.AttestationPolicyReq) (*manager.AttestationPolicyRes, error) {
	policy, err := s.svc.FetchAttestationPolicy(ctx, req.Id)
	if err != nil {
		return nil, err
	}

	return &manager.AttestationPolicyRes{
		Info: policy,
		Id:   req.Id,
	}, nil
}
