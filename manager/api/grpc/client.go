// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"bytes"
	"context"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/ultravioletrs/cocos/manager"
	pkgmanager "github.com/ultravioletrs/cocos/pkg/manager"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
)

var (
	errTerminationFromServer = errors.New("server requested client termination")
	errCorruptedManifest     = errors.New("received manifest may be corrupted")
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

func (client ManagerClient) Process(ctx context.Context, cancel context.CancelFunc) error {
	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		var runReqBuffer bytes.Buffer
		for {
			req, err := client.stream.Recv()
			if err != nil {
				return err
			}

			switch mes := req.Message.(type) {
			case *pkgmanager.ServerStreamMessage_RunReqChunks:
				if len(mes.RunReqChunks.Data) == 0 {
					var runReq pkgmanager.ComputationRunReq
					if err = proto.Unmarshal(runReqBuffer.Bytes(), &runReq); err != nil {
						return errors.Wrap(err, errCorruptedManifest)
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
				}
				if _, err := runReqBuffer.Write(mes.RunReqChunks.Data); err != nil {
					return err
				}

			case *pkgmanager.ServerStreamMessage_TerminateReq:
				cancel()
				return errors.Wrap(errTerminationFromServer, errors.New(mes.TerminateReq.Message))
			case *pkgmanager.ServerStreamMessage_StopComputation:
				msg := &pkgmanager.ClientStreamMessage_StopComputationRes{StopComputationRes: &pkgmanager.StopComputationResponse{
					ComputationId: mes.StopComputation.ComputationId,
				}}
				if err := client.svc.Stop(ctx, mes.StopComputation.ComputationId); err != nil {
					if errors.Contains(err, manager.ErrNotFound) {
						msg.StopComputationRes.Message = err.Error()
						msg.StopComputationRes.Stopped = false
						if err := client.stream.Send(&pkgmanager.ClientStreamMessage{Message: msg}); err != nil {
							return err
						}
						return nil
					}
					msg.StopComputationRes.Message = err.Error()
					msg.StopComputationRes.Stopped = false
					if err := client.stream.Send(&pkgmanager.ClientStreamMessage{Message: msg}); err != nil {
						return err
					}
					return err
				}
				msg.StopComputationRes.Stopped = true
				if err := client.stream.Send(&pkgmanager.ClientStreamMessage{Message: msg}); err != nil {
					return err
				}
			case *pkgmanager.ServerStreamMessage_BackendInfoReq:
				res, err := client.svc.FetchBackendInfo()
				if err != nil {
					return err
				}
				info := &pkgmanager.ClientStreamMessage_BackendInfo{BackendInfo: &pkgmanager.BackendInfo{
					Info: res,
					Id:   mes.BackendInfoReq.Id,
				}}
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
