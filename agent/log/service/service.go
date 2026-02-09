// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package service

import (
	"context"
	"log/slog"

	"github.com/ultravioletrs/cocos/agent/cvms"
	"github.com/ultravioletrs/cocos/agent/log"
	"google.golang.org/protobuf/types/known/emptypb"
)

var _ log.LogCollectorServer = (*LogForwarder)(nil)

type LogForwarder struct {
	log.UnimplementedLogCollectorServer
	cvmsClient cvms.ServiceClient
	logger     *slog.Logger
	logQueue   chan *cvms.ClientStreamMessage
}

func New(logger *slog.Logger, cvmsClient cvms.ServiceClient, queue chan *cvms.ClientStreamMessage) *LogForwarder {
	return &LogForwarder{
		cvmsClient: cvmsClient,
		logger:     logger,
		logQueue:   queue,
	}
}

func (s *LogForwarder) SendLog(ctx context.Context, req *log.LogEntry) (*emptypb.Empty, error) {
	s.logQueue <- &cvms.ClientStreamMessage{
		Message: &cvms.ClientStreamMessage_AgentLog{
			AgentLog: &cvms.AgentLog{
				Message:       req.Message,
				ComputationId: req.ComputationId,
				Level:         req.Level,
				Timestamp:     req.Timestamp,
			},
		},
	}
	return &emptypb.Empty{}, nil
}

func (s *LogForwarder) SendEvent(ctx context.Context, req *log.EventEntry) (*emptypb.Empty, error) {
	s.logQueue <- &cvms.ClientStreamMessage{
		Message: &cvms.ClientStreamMessage_AgentEvent{
			AgentEvent: &cvms.AgentEvent{
				EventType:     req.EventType,
				Timestamp:     req.Timestamp,
				ComputationId: req.ComputationId,
				Details:       req.Details,
				Originator:    req.Originator,
				Status:        req.Status,
			},
		},
	}
	return &emptypb.Empty{}, nil
}
