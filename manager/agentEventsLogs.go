// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"fmt"
	"net"
	"regexp"
	"strconv"

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
		cmpID, err := ms.computationIDFromAddress(conn.RemoteAddr().String())
		if err != nil {
			ms.logger.Warn(err.Error())
			continue
		}
		var message manager.ClientStreamMessage
		if err := proto.Unmarshal(b[:n], &message); err != nil {
			ms.logger.Warn(err.Error())
			continue
		}
		switch mes := message.Message.(type) {
		case *manager.ClientStreamMessage_AgentEvent:
			mes.AgentEvent.ComputationId = cmpID
			ms.eventsChan <- &manager.ClientStreamMessage{Message: mes}
		case *manager.ClientStreamMessage_AgentLog:
			mes.AgentLog.ComputationId = cmpID
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
		return ms.agents[cid], nil
	}
	return "", errFailedToParseCID
}
