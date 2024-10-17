// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package events

import (
	"log/slog"
	"net"

	"github.com/mdlayher/vsock"
	agentevents "github.com/ultravioletrs/cocos/agent/events"
	internalvsock "github.com/ultravioletrs/cocos/internal/vsock"
	"github.com/ultravioletrs/cocos/manager"
	"google.golang.org/protobuf/proto"
)

const (
	ManagerVsockPort     = 9997
	messageSize      int = 1024 * 1024
)

type ReportBrokenConnectionFunc func(address string)

type events struct {
	reportBrokenConnection ReportBrokenConnectionFunc
	lis                    net.Listener
	logger                 *slog.Logger
	eventsChan             chan *manager.ClientStreamMessage
}

func New(logger *slog.Logger, reportBrokenConnection ReportBrokenConnectionFunc, eventsChan chan *manager.ClientStreamMessage) Events {
	l, err := vsock.Listen(ManagerVsockPort, nil)
	if err != nil {
		return nil
	}
	return &events{
		lis:                    l,
		reportBrokenConnection: reportBrokenConnection,
		logger:                 logger,
		eventsChan:             eventsChan,
	}
}

func (e *events) Listen() {
	for {
		conn, err := e.lis.Accept()
		if err != nil {
			e.logger.Warn(err.Error())
			continue
		}

		go e.handleConnection(conn)
	}
}

func (e *events) handleConnection(conn net.Conn) {
	defer conn.Close()

	ackReader := internalvsock.NewAckReader(conn)

	for {
		var message agentevents.EventsLogs
		data, err := ackReader.Read()
		if err != nil {
			go e.reportBrokenConnection(conn.RemoteAddr().String())
			e.logger.Warn(err.Error())
			return
		}

		if err := proto.Unmarshal(data, &message); err != nil {
			e.logger.Warn(err.Error())
			continue
		}

		var mes manager.ClientStreamMessage

		args := []any{}

		switch message.Message.(type) {
		case *agentevents.EventsLogs_AgentEvent:
			args = append(args, slog.Group("agent-event",
				slog.String("event-type", message.GetAgentEvent().GetEventType()),
				slog.String("computation-id", message.GetAgentEvent().GetComputationId()),
				slog.String("status", message.GetAgentEvent().GetStatus()),
				slog.String("originator", message.GetAgentEvent().GetOriginator()),
				slog.String("timestamp", message.GetAgentEvent().GetTimestamp().String()),
				slog.String("details", string(message.GetAgentEvent().GetDetails()))))
			mes = manager.ClientStreamMessage{
				Message: &manager.ClientStreamMessage_AgentEvent{
					AgentEvent: &manager.AgentEvent{
						EventType:     message.GetAgentEvent().GetEventType(),
						ComputationId: message.GetAgentEvent().GetComputationId(),
						Status:        message.GetAgentEvent().GetStatus(),
						Originator:    message.GetAgentEvent().GetOriginator(),
						Timestamp:     message.GetAgentEvent().GetTimestamp(),
						Details:       message.GetAgentEvent().GetDetails(),
					},
				},
			}
		case *agentevents.EventsLogs_AgentLog:
			args = append(args, slog.Group("agent-log",
				slog.String("computation-id", message.GetAgentLog().GetComputationId()),
				slog.String("level", message.GetAgentLog().GetLevel()),
				slog.String("timestamp", message.GetAgentLog().GetTimestamp().String()),
				slog.String("message", message.GetAgentLog().GetMessage())))
			mes = manager.ClientStreamMessage{
				Message: &manager.ClientStreamMessage_AgentLog{
					AgentLog: &manager.AgentLog{
						ComputationId: message.GetAgentLog().GetComputationId(),
						Level:         message.GetAgentLog().GetLevel(),
						Timestamp:     message.GetAgentLog().GetTimestamp(),
						Message:       message.GetAgentLog().GetMessage(),
					},
				},
			}
		}

		e.eventsChan <- &mes

		e.logger.Info("", args...)
	}
}
