// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package events

import (
	"encoding/json"
	"time"

	"github.com/mdlayher/vsock"
	"github.com/ultravioletrs/cocos/pkg/manager"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const VsockEventsPort uint32 = 9998

type service struct {
	service       string
	computationID string
	conn          *vsock.Conn
}

type AgentEvent struct {
	EventType     string          `json:"event_type"`
	Timestamp     time.Time       `json:"timestamp"`
	ComputationID string          `json:"computation_id,omitempty"`
	Details       json.RawMessage `json:"details,omitempty"`
	Originator    string          `json:"originator"`
	Status        string          `json:"status,omitempty"`
}

type Service interface {
	SendEvent(event, status string, details json.RawMessage) error
	Close() error
}

func New(svc, computationID string) (Service, error) {
	conn, err := vsock.Dial(vsock.Host, VsockEventsPort, nil)
	if err != nil {
		return nil, err
	}
	return &service{
		service:       svc,
		computationID: computationID,
		conn:          conn,
	}, nil
}

func (s *service) SendEvent(event, status string, details json.RawMessage) error {

	body := manager.AgentEvent{
		EventType:     event,
		Timestamp:     timestamppb.Now(),
		ComputationId: s.computationID,
		Originator:    s.service,
		Status:        status,
		Details:       details,
	}
	protoBody, err := proto.Marshal(&body)
	if err != nil {
		return err
	}
	if _, err := s.conn.Write(protoBody); err != nil {
		return err
	}
	return nil
}

func (s *service) Close() error {
	return s.conn.Close()
}
