// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strconv"

	"github.com/mdlayher/vsock"
	internalvsock "github.com/ultravioletrs/cocos/internal/vsock"
	"github.com/ultravioletrs/cocos/pkg/manager"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	ManagerVsockPort     = 9997
	messageSize      int = 1024
)

var (
	errFailedToParseCID    = fmt.Errorf("failed to parse computation ID")
	errComputationNotFound = fmt.Errorf("computation not found")
)

// RetrieveAgentEventsLogs Retrieve and forward agent logs and events via vsock.
func (ms *managerService) RetrieveAgentEventsLogs() {
	l, err := vsock.Listen(ManagerVsockPort, nil)
	if err != nil {
		ms.logger.Warn(err.Error())
		return
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			ms.logger.Warn(err.Error())
			continue
		}

		go ms.handleConnection(conn)
	}
}

func (ms *managerService) handleConnection(conn net.Conn) {
	defer conn.Close()

	cmpID, err := ms.computationIDFromAddress(conn.RemoteAddr().String())
	if err != nil {
		ms.logger.Warn(err.Error())
		return
	}

	ackReader := internalvsock.NewAckReader(conn)

	for {
		var message manager.ClientStreamMessage
		data, err := ackReader.Read()
		if err != nil {
			go ms.reportBrokenConnection(cmpID)
			ms.logger.Warn(err.Error())
			return
		}

		if err := proto.Unmarshal(data, &message); err != nil {
			ms.logger.Warn(err.Error())
			continue
		}

		ms.eventsChan <- &message

		args := []any{}

		switch message.Message.(type) {
		case *manager.ClientStreamMessage_AgentEvent:
			args = append(args, slog.Group("agent-event",
				slog.String("event-type", message.GetAgentEvent().GetEventType()),
				slog.String("computation-id", message.GetAgentEvent().GetComputationId()),
				slog.String("status", message.GetAgentEvent().GetStatus()),
				slog.String("originator", message.GetAgentEvent().GetOriginator()),
				slog.String("timestamp", message.GetAgentEvent().GetTimestamp().String()),
				slog.String("details", string(message.GetAgentEvent().GetDetails()))))
		case *manager.ClientStreamMessage_AgentLog:
			args = append(args, slog.Group("agent-log",
				slog.String("computation-id", message.GetAgentLog().GetComputationId()),
				slog.String("level", message.GetAgentLog().GetLevel()),
				slog.String("timestamp", message.GetAgentLog().GetTimestamp().String()),
				slog.String("message", message.GetAgentLog().GetMessage())))
		}

		ms.logger.Info("", args...)
	}
}

func (ms *managerService) computationIDFromAddress(address string) (string, error) {
	re := regexp.MustCompile(`vm\((\d+)\)`)
	matches := re.FindStringSubmatch(address)

	if len(matches) > 1 {
		cid, err := strconv.Atoi(matches[1])
		if err != nil {
			return "", err
		}
		return ms.findComputationID(cid)
	}
	return "", errFailedToParseCID
}

func (ms *managerService) findComputationID(cid int) (string, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	for cmpID, vm := range ms.vms {
		if vm.GetCID() == cid {
			return cmpID, nil
		}
	}

	return "", errComputationNotFound
}

func (ms *managerService) reportBrokenConnection(cmpID string) {
	ms.eventsChan <- &manager.ClientStreamMessage{
		Message: &manager.ClientStreamMessage_AgentEvent{
			AgentEvent: &manager.AgentEvent{
				EventType:     ms.vms[cmpID].State(),
				ComputationId: cmpID,
				Status:        manager.Disconnected.String(),
				Timestamp:     timestamppb.Now(),
				Originator:    "manager",
			},
		},
	}
}
