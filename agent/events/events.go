// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package events

import (
	"encoding/json"
	"io"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type service struct {
	service       string
	computationID string
	conn          io.Writer
}

//go:generate mockery --name Service --output=./mocks --filename events.go --quiet --note "Copyright (c) Ultraviolet \n // SPDX-License-Identifier: Apache-2.0"
type Service interface {
	SendEvent(event, status string, details json.RawMessage) error
}

func New(svc, computationID string, conn io.Writer) (Service, error) {
	return &service{
		service:       svc,
		computationID: computationID,
		conn:          conn,
	}, nil
}

func (s *service) SendEvent(event, status string, details json.RawMessage) error {
	body := EventsLogs{Message: &EventsLogs_AgentEvent{AgentEvent: &AgentEvent{
		EventType:     event,
		Timestamp:     timestamppb.Now(),
		ComputationId: s.computationID,
		Originator:    s.service,
		Status:        status,
		Details:       details,
	}}}
	protoBody, err := proto.Marshal(&body)
	if err != nil {
		return err
	}
	_, err = s.conn.Write(protoBody)
	return err
}
