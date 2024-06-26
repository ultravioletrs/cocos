// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"bytes"
	"context"
	"errors"
	"io"

	"github.com/ultravioletrs/cocos/manager"
	pkgmanager "github.com/ultravioletrs/cocos/pkg/manager"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
)

var errTerminationFromServer = errors.New("server requested client termination")

type ManagerClient struct {
	stream    pkgmanager.ManagerService_ProcessClient
	svc       manager.Service
	responses chan *pkgmanager.ClientStreamMessage
}

// NewClient returns new gRPC client instance.
func NewClient(stream pkgmanager.ManagerService_ProcessClient, svc manager.Service, responses chan *pkgmanager.ClientStreamMessage) ManagerClient {
	return ManagerClient{
		stream:    stream,
		svc:       svc,
		responses: responses,
	}
}

func (client ManagerClient) Process(ctx context.Context, cancel context.CancelFunc) error {
	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		var data bytes.Buffer
		for {
			req, err := client.stream.Recv()
			if err != nil {
				if err == io.EOF {
					var runReq pkgmanager.ComputationRunReq
					if err = proto.Unmarshal(data.Bytes(), &runReq); err != nil {
						return err
					}
					port, err := client.svc.Run(ctx, &runReq)
					if err != nil {
						return err
					}
					runRes := &pkgmanager.ClientStreamMessage_RunRes{
						RunRes: &pkgmanager.RunResponse{
							AgentPort:     port,
							ComputationId: runReq.Id,
						},
					}
					if err := client.stream.Send(&pkgmanager.ClientStreamMessage{Message: runRes}); err != nil {
						return err
					}
					return nil
				}
				return err
			}

			switch mes := req.Message.(type) {
			case *pkgmanager.ServerStreamMessage_RunReqChunks:
				data.Write(mes.RunReqChunks.Data)

			case *pkgmanager.ServerStreamMessage_TerminateReq:
				cancel()
				return errors.Join(errTerminationFromServer, errors.New(mes.TerminateReq.Message))
			}
		}
	})

	eg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case mes := <-client.responses:
				if err := client.stream.Send(mes); err != nil {
					return err
				}
			}
		}
	})

	return eg.Wait()
}
