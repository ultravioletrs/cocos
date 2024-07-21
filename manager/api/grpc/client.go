// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"
	"errors"

	"github.com/ultravioletrs/cocos/manager"
	pkgmanager "github.com/ultravioletrs/cocos/pkg/manager"
	"golang.org/x/sync/errgroup"
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
		for {
			req, err := client.stream.Recv()
			if err != nil {
				return err
			}
			switch mes := req.Message.(type) {
			case *pkgmanager.ServerStreamMessage_RunReq:
				port, err := client.svc.Run(ctx, mes.RunReq)
				if err != nil {
					return err
				}
				runRes := &pkgmanager.ClientStreamMessage_RunRes{RunRes: &pkgmanager.RunResponse{AgentPort: port, ComputationId: mes.RunReq.Id}}
				if err := client.stream.Send(&pkgmanager.ClientStreamMessage{Message: runRes}); err != nil {
					return err
				}
			case *pkgmanager.ServerStreamMessage_TerminateReq:
				cancel()
				return errors.Join(errTerminationFromServer, errors.New(mes.TerminateReq.Message))
			case *pkgmanager.ServerStreamMessage_StopComputation:
				if err := client.svc.Stop(ctx, mes.StopComputation.ComputationId); err != nil {
					return err
				}
			case *pkgmanager.ServerStreamMessage_BackendInfoReq:
				res, err := client.svc.FetchBackendInfo()
				if err != nil {
					return err
				}
				info := &pkgmanager.ClientStreamMessage_BackendInfo{BackendInfo: &pkgmanager.BackendInfo{Info: res}}
				if err := client.stream.Send(&pkgmanager.ClientStreamMessage{Message: info}); err != nil {
					return err
				}
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
