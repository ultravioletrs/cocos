// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"bytes"
	"context"
	"log/slog"

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
	logger    *slog.Logger
}

// NewClient returns new gRPC client instance.
func NewClient(stream pkgmanager.ManagerService_ProcessClient, svc manager.Service, responses chan *pkgmanager.ClientStreamMessage, logger *slog.Logger) ManagerClient {
	return ManagerClient{
		stream:    stream,
		svc:       svc,
		responses: responses,
		logger:    logger,
	}
}

func (client ManagerClient) Process(ctx context.Context, cancel context.CancelFunc) error {
	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		return client.handleIncomingMessages(ctx)
	})

	eg.Go(func() error {
		return client.handleOutgoingMessages(ctx)
	})

	return eg.Wait()
}

func (client ManagerClient) handleIncomingMessages(ctx context.Context) error {
	var runReqBuffer bytes.Buffer
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			req, err := client.stream.Recv()
			if err != nil {
				return err
			}
			if err := client.processIncomingMessage(ctx, req, &runReqBuffer); err != nil {
				return err
			}
		}
	}
}

func (client ManagerClient) processIncomingMessage(ctx context.Context, req *pkgmanager.ServerStreamMessage, runReqBuffer *bytes.Buffer) error {
	switch mes := req.Message.(type) {
	case *pkgmanager.ServerStreamMessage_RunReqChunks:
		return client.handleRunReqChunks(ctx, mes, runReqBuffer)
	case *pkgmanager.ServerStreamMessage_TerminateReq:
		return client.handleTerminateReq(mes)
	case *pkgmanager.ServerStreamMessage_StopComputation:
		go client.handleStopComputation(ctx, mes)
	case *pkgmanager.ServerStreamMessage_BackendInfoReq:
		go client.handleBackendInfoReq(ctx, mes)
	default:
		return errors.New("unknown message type")
	}
	return nil
}

func (client ManagerClient) handleRunReqChunks(ctx context.Context, mes *pkgmanager.ServerStreamMessage_RunReqChunks, runReqBuffer *bytes.Buffer) error {
	if len(mes.RunReqChunks.Data) == 0 {
		var runReq pkgmanager.ComputationRunReq
		if err := proto.Unmarshal(runReqBuffer.Bytes(), &runReq); err != nil {
			return errors.Wrap(err, errCorruptedManifest)
		}
		go client.executeRun(ctx, &runReq)
	}
	_, err := runReqBuffer.Write(mes.RunReqChunks.Data)
	return err
}

func (client ManagerClient) executeRun(ctx context.Context, runReq *pkgmanager.ComputationRunReq) {
	port, err := client.svc.Run(ctx, runReq)
	if err != nil {
		client.logger.Warn(err.Error())
		return
	}
	runRes := &pkgmanager.ClientStreamMessage_RunRes{
		RunRes: &pkgmanager.RunResponse{
			AgentPort:     port,
			ComputationId: runReq.Id,
		},
	}
	client.sendMessage(&pkgmanager.ClientStreamMessage{Message: runRes})
}

func (client ManagerClient) handleTerminateReq(mes *pkgmanager.ServerStreamMessage_TerminateReq) error {
	return errors.Wrap(errTerminationFromServer, errors.New(mes.TerminateReq.Message))
}

func (client ManagerClient) handleStopComputation(ctx context.Context, mes *pkgmanager.ServerStreamMessage_StopComputation) {
	msg := &pkgmanager.ClientStreamMessage_StopComputationRes{
		StopComputationRes: &pkgmanager.StopComputationResponse{
			ComputationId: mes.StopComputation.ComputationId,
		},
	}
	if err := client.svc.Stop(ctx, mes.StopComputation.ComputationId); err != nil {
		msg.StopComputationRes.Message = err.Error()
	}
	client.sendMessage(&pkgmanager.ClientStreamMessage{Message: msg})
}

func (client ManagerClient) handleBackendInfoReq(ctx context.Context, mes *pkgmanager.ServerStreamMessage_BackendInfoReq) {
	res, err := client.svc.FetchBackendInfo()
	if err != nil {
		client.logger.Warn(err.Error())
		return
	}
	info := &pkgmanager.ClientStreamMessage_BackendInfo{
		BackendInfo: &pkgmanager.BackendInfo{
			Info: res,
			Id:   mes.BackendInfoReq.Id,
		},
	}
	client.sendMessage(&pkgmanager.ClientStreamMessage{Message: info})
}

func (client ManagerClient) handleOutgoingMessages(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case mes := <-client.responses:
			if err := client.stream.Send(mes); err != nil {
				return err
			}
		}
	}
}

func (client ManagerClient) sendMessage(mes *pkgmanager.ClientStreamMessage) {
	select {
	case client.responses <- mes:
		return
	default:
		client.logger.Warn("failed to send message to client")
	}
}
