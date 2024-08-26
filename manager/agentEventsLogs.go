// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"fmt"
	"net"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/mdlayher/vsock"
	"github.com/ultravioletrs/cocos/pkg/manager"
	"google.golang.org/protobuf/proto"
)

const (
	ManagerVsockPort     = 9997
	messageSize      int = 1024
)

var errFailedToParseCID = errors.New("failed to parse cid from remote address")

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
