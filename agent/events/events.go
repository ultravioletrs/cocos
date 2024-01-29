// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package events

import (
	"encoding/json"
	"time"

	"github.com/mdlayher/vsock"
	"github.com/ultravioletrs/cocos/manager/agentevents"
)

type service struct {
	service       string
	computationID string
	conn          *vsock.Conn
}

type Header struct {
	Key   string
	Value string
}

type Service interface {
	SendEvent(event, status string, details json.RawMessage, headers []Header) error
	Close() error
}

func New(svc, computationID string) (Service, error) {
	conn, err := vsock.Dial(vsock.Host, agentevents.VsockEventsPort, nil)
	if err != nil {
		return nil, err
	}
	return &service{
		service:       svc,
		computationID: computationID,
		conn:          conn,
	}, nil
}

func (s *service) SendEvent(event, status string, details json.RawMessage, headers []Header) error {
	body := struct {
		EventType     string          `json:"event_type"`
		Timestamp     time.Time       `json:"timestamp"`
		ComputationID string          `json:"computation_id,omitempty"`
		Details       json.RawMessage `json:"details,omitempty"`
		Originator    string          `json:"originator"`
		Status        string          `json:"status,omitempty"`
	}{
		EventType:     event,
		Timestamp:     time.Now(),
		ComputationID: s.computationID,
		Originator:    s.service,
		Status:        status,
		Details:       details,
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}

	combinedData := struct {
		Headers []Header
		Body    []byte
	}{
		Headers: headers,
		Body:    jsonBody,
	}

	serializedData, err := json.Marshal(combinedData)
	if err != nil {
		return err
	}
	if _, err := s.conn.Write(serializedData); err != nil {
		return err
	}
	return nil
}

func (s *service) Close() error {
	return s.conn.Close()
}
