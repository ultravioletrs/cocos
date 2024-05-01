// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"github.com/ultravioletrs/cocos/pkg/manager"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

var _ manager.ManagerServiceServer = (*grpcServer)(nil)

type grpcServer struct {
	manager.UnimplementedManagerServiceServer
	incoming chan *manager.ClientStreamMessage
	svc      Service
}

type Service interface {
	Run(ipAddress string, runReqChan chan *manager.ServerStreamMessage, authInfo credentials.AuthInfo)
}

// NewServer returns new AuthServiceServer instance.
func NewServer(incoming chan *manager.ClientStreamMessage, svc Service) manager.ManagerServiceServer {
	return &grpcServer{
		incoming: incoming,
		svc:      svc,
	}
}

func (s *grpcServer) Process(stream manager.ManagerService_ProcessServer) error {
	runReqChan := make(chan *manager.ServerStreamMessage)
	client, ok := peer.FromContext(stream.Context())
	if ok {
		go s.svc.Run(client.Addr.String(), runReqChan, client.AuthInfo)
	}
	eg, ctx := errgroup.WithContext(stream.Context())

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
		for {
			select {
			case <-ctx.Done():
				return nil
			case req := <-runReqChan:
				if err := stream.Send(req); err != nil {
					return err
				}
			}
		}
	})
	return eg.Wait()
}
