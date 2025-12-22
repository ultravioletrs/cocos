// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/ultravioletrs/cocos/agent/cvms"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/proto"
)

var (
	_                cvms.ServiceServer = (*grpcServer)(nil)
	ErrUnexpectedMsg                    = errors.New("unknown message type")
)

const (
	bufferSize    = 1024 * 1024 // 1 MB
	runReqTimeout = 30 * time.Second
)

type SendFunc func(*cvms.ServerStreamMessage) error

type grpcServer struct {
	cvms.UnimplementedServiceServer
	incoming chan *cvms.ClientStreamMessage
	svc      Service
}

type Service interface {
	Run(ctx context.Context, ipAddress string, sendMessage SendFunc, authInfo credentials.AuthInfo)
}

// NewServer returns new AuthServiceServer instance.
func NewServer(incoming chan *cvms.ClientStreamMessage, svc Service) cvms.ServiceServer {
	return &grpcServer{
		incoming: incoming,
		svc:      svc,
	}
}

func (s *grpcServer) Process(stream cvms.Service_ProcessServer) error {
	client, ok := peer.FromContext(stream.Context())
	if !ok {
		return errors.New("failed to get peer info")
	}

	slog.Info("client connected to cvms server", "address", client.Addr.String())

	eg, ctx := errgroup.WithContext(stream.Context())

	eg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				slog.Info("receive goroutine context done", "address", client.Addr.String())
				return ctx.Err()
			default:
				req, err := stream.Recv()
				if err != nil {
					slog.Error("failed to receive from stream", "address", client.Addr.String(), "error", err)
					return err
				}
				s.incoming <- req
			}
		}
	})

	eg.Go(func() error {
		sendMessage := func(msg *cvms.ServerStreamMessage) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				switch m := msg.Message.(type) {
				case *cvms.ServerStreamMessage_RunReq:
					return s.sendRunReqInChunks(stream, m.RunReq)
				default:
					return stream.Send(msg)
				}
			}
		}

		s.svc.Run(ctx, client.Addr.String(), sendMessage, client.AuthInfo)
		slog.Info("send goroutine Run() returned", "address", client.Addr.String())
		return nil
	})

	err := eg.Wait()
	slog.Info("stream closed", "address", client.Addr.String(), "error", err)
	return err
}

func (s *grpcServer) sendRunReqInChunks(stream cvms.Service_ProcessServer, runReq *cvms.ComputationRunReq) error {
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

		chunk := &cvms.ServerStreamMessage{
			Message: &cvms.ServerStreamMessage_RunReqChunks{
				RunReqChunks: &cvms.RunReqChunks{
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
