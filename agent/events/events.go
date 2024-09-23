// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package events

import (
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/ultravioletrs/cocos/pkg/manager"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const retryInterval = 5 * time.Second

type service struct {
	service        string
	computationID  string
	conn           io.Writer
	cachedMessages [][]byte
	mutex          sync.Mutex
	stopRetry      chan struct{}
}

type AgentEvent struct {
	EventType     string          `json:"event_type"`
	Timestamp     time.Time       `json:"timestamp"`
	ComputationID string          `json:"computation_id,omitempty"`
	Details       json.RawMessage `json:"details,omitempty"`
	Originator    string          `json:"originator"`
	Status        string          `json:"status,omitempty"`
}

//go:generate mockery --name Service --output=./mocks --filename events.go --quiet --note "Copyright (c) Ultraviolet \n // SPDX-License-Identifier: Apache-2.0"
type Service interface {
	SendEvent(event, status string, details json.RawMessage) error
	Close()
}

func New(svc, computationID string, conn io.Writer) (Service, error) {
	s := &service{
		service:        svc,
		computationID:  computationID,
		conn:           conn,
		cachedMessages: make([][]byte, 0),
		stopRetry:      make(chan struct{}),
	}

	go s.periodicRetry()

	return s, nil
}

func (s *service) SendEvent(event, status string, details json.RawMessage) error {
	body := manager.ClientStreamMessage{Message: &manager.ClientStreamMessage_AgentEvent{AgentEvent: &manager.AgentEvent{
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

	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, err := s.conn.Write(protoBody); err != nil {
		s.cachedMessages = append(s.cachedMessages, protoBody)
		return err
	}

	return nil
}

func (s *service) periodicRetry() {
	ticker := time.NewTicker(retryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.retrySendCachedMessages()
		case <-s.stopRetry:
			return
		}
	}
}

func (s *service) retrySendCachedMessages() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	tmp := [][]byte{}
	for _, msg := range s.cachedMessages {
		if _, err := s.conn.Write(msg); err != nil {
			tmp = append(tmp, msg)
		}
	}
	s.cachedMessages = tmp
}

func (s *service) Close() {
	close(s.stopRetry)
}
