// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"fmt"
	"net"
	"regexp"
	"strconv"

	"github.com/mdlayher/vsock"
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

		go ms.handleConnections(conn)
	}
}

func (ms *managerService) handleConnections(conn net.Conn) {
	defer conn.Close()
	for {
		b := make([]byte, messageSize)
		n, err := conn.Read(b)
		if err != nil {
			ms.logger.Warn(err.Error())
			cmpID, err := ms.computationIDFromAddress(conn.RemoteAddr().String())
			if err != nil {
				ms.logger.Warn(err.Error())
				continue
			}
			go ms.reportBrokenConnection(cmpID)
			return
		}
		var message manager.ClientStreamMessage
		if err := proto.Unmarshal(b[:n], &message); err != nil {
			ms.logger.Warn(err.Error())
			continue
		}
		cmpID := ""
		switch mes := message.Message.(type) {
		case *manager.ClientStreamMessage_AgentEvent:
			cmpID = mes.AgentEvent.ComputationId
			ms.eventsChan <- &manager.ClientStreamMessage{Message: mes}
		case *manager.ClientStreamMessage_AgentLog:
			cmpID = mes.AgentLog.ComputationId
			ms.eventsChan <- &manager.ClientStreamMessage{Message: mes}
		default:
			ms.logger.Warn("Unexpected agent log or event type")
		}

		ms.logger.Info(fmt.Sprintf("Agent Log/Event, Computation ID: %s, Message: %s", cmpID, message.String()))
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
				EventType:     "vm running",
				ComputationId: cmpID,
				Status:        "disconnected",
				Timestamp:     timestamppb.Now(),
				Originator:    "manager",
			},
		},
	}
}
