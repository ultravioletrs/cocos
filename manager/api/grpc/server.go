// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"bytes"
	"io"

	"github.com/ultravioletrs/cocos/pkg/manager"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"
)

var _ manager.ManagerServiceServer = (*grpcServer)(nil)

const bufferSize = 1024 * 1024 // 1 MB

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
				data, err := proto.Marshal(req.GetRunReq())
				if err != nil {
					return err
				}

				dataBuffer := bytes.NewBuffer(data)
				buf := make([]byte, bufferSize)
				for {
					n, err := dataBuffer.Read(buf)
					if err == io.EOF {
						break
					}

					chunk := &manager.ServerStreamMessage{
						Message: &manager.ServerStreamMessage_RunReqChunks{
							RunReqChunks: &manager.RunReqChunks{
								Data: buf[:n],
							},
						},
					}
					if err := stream.Send(chunk); err != nil {
						return err
					}
				}
			}
		}
	})
	return eg.Wait()
}
