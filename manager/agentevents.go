// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"net"

	"github.com/mdlayher/vsock"
	"github.com/ultravioletrs/cocos/pkg/manager"
	"google.golang.org/protobuf/proto"
)

func (s *managerService) retrieveAgentEvents() {
	l, err := vsock.Listen(9998, nil)
	if err != nil {
		s.logger.Warn(err.Error())
		return
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			s.logger.Warn(err.Error())
			continue
		}
		go s.handleEventsConnections(conn)
	}
}

func (s *managerService) handleEventsConnections(conn net.Conn) {
	defer conn.Close()
	for {
		b := make([]byte, messageSize)
		n, err := conn.Read(b)
		if err != nil {
			s.logger.Warn(err.Error())
			return
		}
		var ev manager.AgentEvent
		if err := proto.Unmarshal(b[:n], &ev); err != nil {
			s.logger.Warn(err.Error())
			continue
		}
		s.eventsChan <- &manager.ClientStreamMessage{
			Message: &manager.ClientStreamMessage_AgentEvent{AgentEvent: &ev},
		}
	}
}
