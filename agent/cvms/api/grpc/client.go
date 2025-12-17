// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/agent/cvms"
	"github.com/ultravioletrs/cocos/agent/cvms/api/grpc/storage"
	"github.com/ultravioletrs/cocos/agent/cvms/server"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"github.com/ultravioletrs/cocos/pkg/clients/grpc"
	"github.com/ultravioletrs/cocos/pkg/ingress"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
)

const (
	reconnectInterval = 5 * time.Second
	sendTimeout       = 5 * time.Second
)

var (
	errCorruptedManifest  = errors.New("received manifest may be corrupted")
	errUnknownMessageType = errors.New("unknown message type")
)

type PendingMessage struct {
	Message *cvms.ClientStreamMessage
	Time    time.Time
}

type CVMSClient struct {
	mu            sync.Mutex
	stream        cvms.Service_ProcessClient
	svc           agent.Service
	messageQueue  chan *cvms.ClientStreamMessage
	logger        *slog.Logger
	runReqManager *runRequestManager
	sp            server.AgentServer
	ingressProxy  ingress.ProxyServer
	storage       storage.Storage
	reconnectFn   func(context.Context) (grpc.Client, cvms.Service_ProcessClient, error)
	grpcClient    grpc.Client
}

// NewClient returns new gRPC client instance.
func NewClient(stream cvms.Service_ProcessClient, svc agent.Service, messageQueue chan *cvms.ClientStreamMessage, logger *slog.Logger, sp server.AgentServer, ingressProxy ingress.ProxyServer, storageDir string, reconnectFn func(context.Context) (grpc.Client, cvms.Service_ProcessClient, error), grpcClient grpc.Client) (*CVMSClient, error) {
	store, err := storage.NewFileStorage(storageDir)
	if err != nil {
		return nil, err
	}

	return &CVMSClient{
		stream:        stream,
		svc:           svc,
		messageQueue:  messageQueue,
		logger:        logger,
		runReqManager: newRunRequestManager(),
		sp:            sp,
		ingressProxy:  ingressProxy,
		storage:       store,
		reconnectFn:   reconnectFn,
		grpcClient:    grpcClient,
	}, nil
}

func (client *CVMSClient) Process(ctx context.Context, cancel context.CancelFunc) error {
	for {
		err := client.processWithRetry(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}

		slog.Info("Connection lost, attempting to reconnect...")
		client.logger.Info("Connection lost, attempting to reconnect...", "error", err)
		time.Sleep(reconnectInterval)

		grpcClient, stream, err := client.reconnectFn(ctx)
		if err != nil {
			client.logger.Error("Failed to reconnect", "error", err)
			continue
		}

		client.mu.Lock()
		client.stream = stream
		client.grpcClient = grpcClient
		client.mu.Unlock()
	}
}

func (client *CVMSClient) processWithRetry(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		return client.handleIncomingMessages(ctx)
	})

	eg.Go(func() error {
		return client.handleOutgoingMessages(ctx)
	})

	return eg.Wait()
}

func (client *CVMSClient) handleIncomingMessages(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			req, err := client.stream.Recv()
			if err != nil {
				slog.Error("Failed to receive message from stream", "error", err)
				return err
			}
			slog.Debug("Received message from cms", "type", fmt.Sprintf("%T", req.Message))
			if err := client.processIncomingMessage(ctx, req); err != nil {
				slog.Error("Failed to process incoming message", "error", err)
				return err
			}
		}
	}
}

func (client *CVMSClient) handleOutgoingMessages(ctx context.Context) error {
	pendingMsgs, err := client.storage.Load()
	if err != nil {
		client.logger.Error("Failed to load pending messages", "error", err)
	} else {
		client.sendPendingMessages(pendingMsgs)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg := <-client.messageQueue:
			if err := client.sendStreamMessage(msg); err != nil {
				if err := client.storage.Add(msg); err != nil {
					client.logger.Error("Failed to store pending message", "error", err)
				}
				client.logger.Error("Failed to send message, stored for retry", "error", err)
			}
		}
	}
}

func (client *CVMSClient) sendStreamMessage(msg *cvms.ClientStreamMessage) error {
	client.mu.Lock()
	defer client.mu.Unlock()

	return client.stream.Send(msg)
}

func (client *CVMSClient) sendPendingMessages(pending []storage.Message) {
	for _, pm := range pending {
		if err := client.sendStreamMessage(pm.Message); err != nil {
			if err := client.storage.Add(pm.Message); err != nil {
				client.logger.Error("Failed to store pending message", "error", err)
			}
			client.logger.Error("Failed to resend pending message", "error", err)
		} else {
			client.logger.Info("Successfully resent pending message")
		}
	}

	if err := client.storage.Clear(); err != nil {
		client.logger.Error("Failed to clear pending messages", "error", err)
	}
}

func (client *CVMSClient) processIncomingMessage(ctx context.Context, req *cvms.ServerStreamMessage) error {
	switch mes := req.Message.(type) {
	case *cvms.ServerStreamMessage_RunReqChunks:
		return client.handleRunReqChunks(ctx, mes)
	case *cvms.ServerStreamMessage_StopComputation:
		go client.handleStopComputation(ctx, mes)
	case *cvms.ServerStreamMessage_AgentStateReq:
		client.handleAgentStateReq(mes)
	case *cvms.ServerStreamMessage_DisconnectReq:
		client.logger.Info("Received disconnect request")
		client.mu.Lock()
		if err := client.grpcClient.Close(); err != nil {
			client.logger.Error("Failed to close gRPC client", "error", err)
		}
		client.mu.Unlock()
	default:
		return errUnknownMessageType
	}
	return nil
}

func (client *CVMSClient) handleAgentStateReq(mes *cvms.ServerStreamMessage_AgentStateReq) {
	state := client.svc.State()

	msg := &cvms.ClientStreamMessage_AgentStateRes{
		AgentStateRes: &cvms.AgentStateRes{
			State: state,
			Id:    mes.AgentStateReq.Id,
		},
	}

	client.sendMessage(&cvms.ClientStreamMessage{Message: msg})
}

func (client *CVMSClient) handleRunReqChunks(ctx context.Context, msg *cvms.ServerStreamMessage_RunReqChunks) error {
	client.logger.Debug("Received RunReq chunk", "id", msg.RunReqChunks.Id, "size", len(msg.RunReqChunks.Data), "isLast", msg.RunReqChunks.IsLast)
	buffer, complete := client.runReqManager.addChunk(msg.RunReqChunks.Id, msg.RunReqChunks.Data, msg.RunReqChunks.IsLast)

	if complete {
		client.logger.Info("Received complete computation run request", "id", msg.RunReqChunks.Id, "totalSize", len(buffer))
		var runReq cvms.ComputationRunReq
		if err := proto.Unmarshal(buffer, &runReq); err != nil {
			return errors.Wrap(err, errCorruptedManifest)
		}

		client.logger.Info("Starting computation execution", "computationId", runReq.Id, "name", runReq.Name)
		go client.executeRun(ctx, &runReq)
	}

	return nil
}

func (client *CVMSClient) executeRun(ctx context.Context, runReq *cvms.ComputationRunReq) {
	ac := agent.Computation{
		ID:          runReq.Id,
		Name:        runReq.Name,
		Description: runReq.Description,
	}

	if runReq.Algorithm != nil {
		ac.Algorithm = agent.Algorithm{
			Hash:    [32]byte(runReq.Algorithm.Hash),
			UserKey: runReq.Algorithm.UserKey,
		}
	}

	for _, ds := range runReq.Datasets {
		ac.Datasets = append(ac.Datasets, agent.Dataset{
			Hash:    [32]byte(ds.Hash),
			UserKey: ds.UserKey,
		})
	}

	for _, rc := range runReq.ResultConsumers {
		ac.ResultConsumers = append(ac.ResultConsumers, agent.ResultConsumer{
			UserKey: rc.UserKey,
		})
	}

	if err := client.svc.InitComputation(ctx, ac); err != nil {
		client.logger.Warn(err.Error())
		return
	}

	ccPlatform := attestation.CCPlatform()

	client.mu.Lock()
	defer client.mu.Unlock()

	if runReq.AgentConfig == nil {
		runReq.AgentConfig = &cvms.AgentConfig{}
	}

	runRes := &cvms.ClientStreamMessage_RunRes{
		RunRes: &cvms.RunResponse{
			ComputationId: runReq.Id,
		},
	}

	if err := client.sp.Start(agent.AgentConfig{
		Port:         runReq.AgentConfig.Port,
		CertFile:     runReq.AgentConfig.CertFile,
		KeyFile:      runReq.AgentConfig.KeyFile,
		ServerCAFile: runReq.AgentConfig.ServerCaFile,
		ClientCAFile: runReq.AgentConfig.ClientCaFile,
		AttestedTls:  runReq.AgentConfig.AttestedTls,
	}, ac); err != nil {
		client.logger.Warn(err.Error())
		runRes.RunRes.Error = err.Error()
	}

	// Start ingress proxy if available
	if client.ingressProxy != nil {
		if err := client.ingressProxy.Start(
			ingress.AgentConfigToProxyConfig(agent.AgentConfig{
				Port:         runReq.AgentConfig.Port,
				CertFile:     runReq.AgentConfig.CertFile,
				KeyFile:      runReq.AgentConfig.KeyFile,
				ServerCAFile: runReq.AgentConfig.ServerCaFile,
				ClientCAFile: runReq.AgentConfig.ClientCaFile,
				AttestedTls:  runReq.AgentConfig.AttestedTls,
			}),
			ingress.ComputationToProxyContext(ac),
		); err != nil {
			client.logger.Warn(fmt.Sprintf("failed to start ingress proxy: %s", err.Error()))
		}
	}

	defer func() {
		if ccPlatform == attestation.Azure || ccPlatform == attestation.SNPvTPM {
			cmpJson, err := json.Marshal(ac)
			if err != nil {
				client.logger.Error(err.Error())
				return
			}
			if err = vtpm.ExtendPCR(vtpm.PCR16, cmpJson); err != nil {
				client.logger.Error(err.Error())
				return
			}
		}
	}()

	client.sendMessage(&cvms.ClientStreamMessage{Message: runRes})
}

func (client *CVMSClient) handleStopComputation(ctx context.Context, mes *cvms.ServerStreamMessage_StopComputation) {
	msg := &cvms.ClientStreamMessage_StopComputationRes{
		StopComputationRes: &cvms.StopComputationResponse{
			ComputationId: mes.StopComputation.ComputationId,
		},
	}
	if err := client.svc.StopComputation(ctx); err != nil {
		msg.StopComputationRes.Message = err.Error()
	}

	client.mu.Lock()
	if err := client.sp.Stop(); err != nil {
		msg.StopComputationRes.Message = err.Error()
	}
	// Stop ingress proxy if available
	if client.ingressProxy != nil {
		if err := client.ingressProxy.Stop(); err != nil {
			client.logger.Warn(fmt.Sprintf("failed to stop ingress proxy: %s", err.Error()))
		}
	}
	client.mu.Unlock()

	client.sendMessage(&cvms.ClientStreamMessage{Message: msg})
}

func (client *CVMSClient) sendMessage(mes *cvms.ClientStreamMessage) {
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
