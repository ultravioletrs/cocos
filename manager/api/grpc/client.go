// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/ultravioletrs/cocos/manager"
	pkgmanager "github.com/ultravioletrs/cocos/pkg/manager"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
)

var (
	errTerminationFromServer = errors.New("server requested client termination")
	errCorruptedManifest     = errors.New("received manifest may be corrupted")
	sendTimeout              = 5 * time.Second
)

type ManagerClient struct {
	stream        pkgmanager.ManagerService_ProcessClient
	svc           manager.Service
	messageQueue  chan *pkgmanager.ClientStreamMessage
	logger        *slog.Logger
	runReqManager *runRequestManager
}

// NewClient returns new gRPC client instance.
func NewClient(stream pkgmanager.ManagerService_ProcessClient, svc manager.Service, messageQueue chan *pkgmanager.ClientStreamMessage, logger *slog.Logger) ManagerClient {
	return ManagerClient{
		stream:        stream,
		svc:           svc,
		messageQueue:  messageQueue,
		logger:        logger,
		runReqManager: newRunRequestManager(),
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
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			req, err := client.stream.Recv()
			if err != nil {
				return err
			}
			if err := client.processIncomingMessage(ctx, req); err != nil {
				return err
			}
		}
	}
}

func (client ManagerClient) processIncomingMessage(ctx context.Context, req *pkgmanager.ServerStreamMessage) error {
	switch mes := req.Message.(type) {
	case *pkgmanager.ServerStreamMessage_RunReqChunks:
		return client.handleRunReqChunks(ctx, mes)
	case *pkgmanager.ServerStreamMessage_TerminateReq:
		return client.handleTerminateReq(mes)
	case *pkgmanager.ServerStreamMessage_StopComputation:
		go client.handleStopComputation(ctx, mes)
	case *pkgmanager.ServerStreamMessage_BackendInfoReq:
		go client.handleBackendInfoReq(mes)
	default:
		return errors.New("unknown message type")
	}
	return nil
}

func (client *ManagerClient) handleRunReqChunks(ctx context.Context, mes *pkgmanager.ServerStreamMessage_RunReqChunks) error {
	buffer, complete := client.runReqManager.addChunk(mes.RunReqChunks.Id, mes.RunReqChunks.Data, mes.RunReqChunks.IsLast)

	if complete {
		var runReq pkgmanager.ComputationRunReq
		if err := proto.Unmarshal(buffer, &runReq); err != nil {
			return errors.Wrap(err, errCorruptedManifest)
		}

		go client.executeRun(ctx, &runReq)
	}

	return nil
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

func (client ManagerClient) handleBackendInfoReq(mes *pkgmanager.ServerStreamMessage_BackendInfoReq) {
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
		case mes := <-client.messageQueue:
			if err := client.stream.Send(mes); err != nil {
				return err
			}
		}
	}
}

func (client ManagerClient) sendMessage(mes *pkgmanager.ClientStreamMessage) {
	ctx, cancel := context.WithTimeout(context.Background(), sendTimeout)
	defer cancel()

	select {
	case client.messageQueue <- mes:
	case <-ctx.Done():
		client.logger.Warn("Failed to send message: timeout exceeded")
	}
}

type runRequestManager struct {
	requests map[string]*runRequest
	mu       sync.Mutex
}

type runRequest struct {
	buffer    []byte
	lastChunk time.Time
	timer     *time.Timer
}

func newRunRequestManager() *runRequestManager {
	return &runRequestManager{
		requests: make(map[string]*runRequest),
	}
}

func (m *runRequestManager) addChunk(id string, chunk []byte, isLast bool) ([]byte, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	req, exists := m.requests[id]
	if !exists {
		req = &runRequest{
			buffer:    make([]byte, 0),
			lastChunk: time.Now(),
			timer:     time.AfterFunc(runReqTimeout, func() { m.timeoutRequest(id) }),
		}
		m.requests[id] = req
	}

	req.buffer = append(req.buffer, chunk...)
	req.lastChunk = time.Now()
	req.timer.Reset(runReqTimeout)

	if isLast {
		delete(m.requests, id)
		req.timer.Stop()
		return req.buffer, true
	}

	return nil, false
}

func (m *runRequestManager) timeoutRequest(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.requests, id)
	// Log timeout or handle it as needed
}
