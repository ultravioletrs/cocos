// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"

	"github.com/ultravioletrs/cocos/manager"
	"golang.org/x/sync/errgroup"
)

type grpcServer struct {
	manager.UnimplementedManagerServiceServer
	incoming  chan *manager.ClientStreamMessage
	responses chan *manager.ComputationRunReq
	ctx       context.Context
}

// NewServer returns new AuthServiceServer instance.
func NewServer(ctx context.Context, incoming chan *manager.ClientStreamMessage, responses chan *manager.ComputationRunReq) manager.ManagerServiceServer {
	return &grpcServer{
		incoming:  incoming,
		responses: responses,
	}
}

func (s *grpcServer) Process(stream manager.ManagerService_ProcessServer) error {
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
		for resp := range s.responses {
			if err := stream.Send(resp); err != nil {
				return err
			}
		}
		return nil
	})

	return eg.Wait()
}
