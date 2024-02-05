// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"

	"github.com/ultravioletrs/cocos/manager"
	"google.golang.org/grpc/peer"
)

type grpcServer struct {
	manager.UnimplementedManagerServiceServer
	incoming chan *manager.ClientStreamMessage
	ctx      context.Context
	svc      Service
}

type Service interface {
	Run(ipAddress string) manager.ComputationRunReq
}

// NewServer returns new AuthServiceServer instance.
func NewServer(ctx context.Context, incoming chan *manager.ClientStreamMessage, svc Service) manager.ManagerServiceServer {
	return &grpcServer{
		incoming: incoming,
		svc:      svc,
	}
}

func (s *grpcServer) Process(stream manager.ManagerService_ProcessServer) error {
	for {
		req, err := stream.Recv()
		if err != nil {
			return err
		}
		switch req.Message.(type) {
		case *manager.ClientStreamMessage_WhoamiRequest:
			peer, ok := peer.FromContext(stream.Context())
			if ok {
				req := s.svc.Run(peer.Addr.String())
				if err := stream.Send(&req); err != nil {
					return err
				}
			}

		}
		s.incoming <- req
	}
}
