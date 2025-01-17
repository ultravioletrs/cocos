// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package events

import (
	"encoding/json"

	"github.com/ultravioletrs/cocos/agent/cvms"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type service struct {
	service string
	queue   chan *cvms.ClientStreamMessage
}

type Service interface {
	SendEvent(cmpID, event, status string, details json.RawMessage)
}

func New(svc string, queue chan *cvms.ClientStreamMessage) (Service, error) {
	return &service{
		service: svc,
		queue:   queue,
	}, nil
}

func (s *service) SendEvent(cmpID, event, status string, details json.RawMessage) {
	s.queue <- &cvms.ClientStreamMessage{
		Message: &cvms.ClientStreamMessage_AgentEvent{
			AgentEvent: &cvms.AgentEvent{
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
