// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"

	"github.com/ultravioletrs/cocos/manager"
	pkgmanager "github.com/ultravioletrs/cocos/pkg/manager"
	"golang.org/x/sync/errgroup"
)

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

func (client ManagerClient) Process(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		for {
			req, err := client.stream.Recv()
			if err != nil {
				return err
			}
			port, err := client.svc.Run(ctx, req)
			if err != nil {
				return err
			}
			runRes := &pkgmanager.ClientStreamMessage_RunRes{RunRes: &pkgmanager.RunResponse{AgentPort: port, ComputationId: req.Id}}
			if err := client.stream.Send(&pkgmanager.ClientStreamMessage{Message: runRes}); err != nil {
				return err
			}
		}
	})

	eg.Go(func() error {
		for mes := range client.responses {
			if err := client.stream.Send(mes); err != nil {
				return err
			}
		}
		return nil
	})

	return eg.Wait()
}
