// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"
	"errors"

	"github.com/ultravioletrs/cocos/pkg/manager"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/peer"
)

var _ manager.ManagerServiceServer = (*grpcServer)(nil)

type grpcServer struct {
	manager.UnimplementedManagerServiceServer
	incoming chan *manager.ClientStreamMessage
	svc      Service
	ctx      context.Context
}

type Service interface {
	Run(ipAddress string, runReqChan chan *manager.ComputationRunReq)
	Heartbeat(ipAddress string)
}

// NewServer returns new AuthServiceServer instance.
func NewServer(ctx context.Context, incoming chan *manager.ClientStreamMessage, svc Service) manager.ManagerServiceServer {
	return &grpcServer{
		incoming: incoming,
		svc:      svc,
		ctx:      ctx,
	}
}

func (s *grpcServer) Process(stream manager.ManagerService_ProcessServer) error {
	runReqChan := make(chan *manager.ComputationRunReq)
	client, ok := peer.FromContext(stream.Context())
	if ok {
		go s.svc.Run(client.Addr.String(), runReqChan)
	}
	eg, _ := errgroup.WithContext(s.ctx)

	eg.Go(func() error {
		for {
			req, err := stream.Recv()
			if err != nil {
				return err
			}

			s.incoming <- req
		}
	})

	eg.Go(func() error {
		for runReq := range runReqChan {
			if err := stream.Send(runReq); err != nil {
				return err
			}
		}
		return nil
	})
	return eg.Wait()
}

func (s *grpcServer) Heartbeat(stream manager.ManagerService_HeartbeatServer) error {
	p, ok := peer.FromContext(stream.Context())
	if !ok {
		return errors.New("failed to get peer from context")
	}
	for {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		s.svc.Heartbeat(p.Addr.String())
	}
}
