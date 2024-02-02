// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"encoding/json"
	"net"

	"github.com/mdlayher/vsock"
	"github.com/ultravioletrs/cocos/agent/events"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	svc string = "agent"
)

func (s *managerService) retrieveAgentEvents() {
	l, err := vsock.Listen(events.VsockEventsPort, nil)
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
		var ev events.AgentEvent
		if err := json.Unmarshal(b[:n], &ev); err != nil {
			s.logger.Warn(err.Error())
			continue
		}
		s.eventsChan <- &ClientStreamMessage{
			Message: &ClientStreamMessage_AgentEvent{AgentEvent: &AgentEvent{
				EventType:     ev.EventType,
				Timestamp:     timestamppb.New(ev.Timestamp),
				ComputationId: ev.ComputationID,
				Details:       ev.Details,
				Originator:    ev.Originator,
				Status:        ev.Status,
			}},
		}
	}
}
