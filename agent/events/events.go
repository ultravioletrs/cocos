// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package events

import (
	"encoding/json"

	"github.com/ultravioletrs/cocos/agent/cvm"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type service struct {
	service string
	queue   chan *cvm.ClientStreamMessage
}

type Service interface {
	SendEvent(cmpID, event, status string, details json.RawMessage)
}

func New(svc string, queue chan *cvm.ClientStreamMessage) (Service, error) {
	return &service{
		service: svc,
		queue:   queue,
	}, nil
}

func (s *service) SendEvent(cmpID, event, status string, details json.RawMessage) {
	s.queue <- &cvm.ClientStreamMessage{
		Message: &cvm.ClientStreamMessage_AgentEvent{
			AgentEvent: &cvm.AgentEvent{
				EventType:     event,
				Timestamp:     timestamppb.Now(),
				ComputationId: cmpID,
				Originator:    s.service,
				Status:        status,
				Details:       details,
			},
		},
	}
}
