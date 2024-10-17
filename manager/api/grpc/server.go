// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"time"

	"github.com/ultravioletrs/cocos/manager"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"
)

var (
	_                manager.ManagerServiceServer = (*grpcServer)(nil)
	ErrUnexpectedMsg                              = errors.New("unknown message type")
)

const (
	bufferSize    = 1024 * 1024 // 1 MB
	runReqTimeout = 30 * time.Second
)

type SendFunc func(*manager.ServerStreamMessage) error

type grpcServer struct {
	manager.UnimplementedManagerServiceServer
	incoming chan *manager.ClientStreamMessage
	svc      Service
}

type Service interface {
	Run(ctx context.Context, ipAddress string, sendMessage SendFunc, authInfo credentials.AuthInfo)
}

// NewServer returns new AuthServiceServer instance.
func NewServer(incoming chan *manager.ClientStreamMessage, svc Service) manager.ManagerServiceServer {
	return &grpcServer{
		incoming: incoming,
		svc:      svc,
	}
}

func (s *grpcServer) Process(stream manager.ManagerService_ProcessServer) error {
	client, ok := peer.FromContext(stream.Context())
	if !ok {
		return errors.New("failed to get peer info")
	}

	eg, ctx := errgroup.WithContext(stream.Context())

	eg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				req, err := stream.Recv()
				if err != nil {
					return err
				}
				s.incoming <- req
			}
		}
	})

	eg.Go(func() error {
		sendMessage := func(msg *manager.ServerStreamMessage) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				switch m := msg.Message.(type) {
				case *manager.ServerStreamMessage_RunReq:
					return s.sendRunReqInChunks(stream, m.RunReq)
				default:
					return stream.Send(msg)
				}
			}
		}

		s.svc.Run(ctx, client.Addr.String(), sendMessage, client.AuthInfo)
		return nil
	})

	return eg.Wait()
}

func (s *grpcServer) sendRunReqInChunks(stream manager.ManagerService_ProcessServer, runReq *manager.ComputationRunReq) error {
	data, err := proto.Marshal(runReq)
	if err != nil {
		return err
	}

	dataBuffer := bytes.NewBuffer(data)
	buf := make([]byte, bufferSize)

	for {
		n, err := dataBuffer.Read(buf)
		isLast := false

		if err == io.EOF {
			isLast = true
		} else if err != nil {
			return err
		}

		chunk := &manager.ServerStreamMessage{
			Message: &manager.ServerStreamMessage_RunReqChunks{
				RunReqChunks: &manager.RunReqChunks{
					Id:     runReq.Id,
					Data:   buf[:n],
					IsLast: isLast,
				},
			},
		}

		if err := stream.Send(chunk); err != nil {
			return err
		}

		if isLast {
			break
		}
	}

	return nil
}
