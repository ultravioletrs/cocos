// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package events

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"
)

var errFailedToCreateNotification = errors.New("failed to create notification on server")

type service struct {
	service   string
	serverUrl string
}

type Event struct {
	EventType     string          `json:"event_type"`
	Timestamp     time.Time       `json:"timestamp"`
	ComputationID string          `json:"computation_id,omitempty"`
	Details       json.RawMessage `json:"details,omitempty"`
	Originator    string          `json:"originator"`
	Status        string          `json:"status,omitempty"`
}

type Service interface {
	SendEvent(event, computationId, computationKey, status string, details json.RawMessage) error
	SendRaw(body []byte, headers map[string]string) error
}

func New(svc, serverUrl string) Service {
	return &service{
		service:   svc,
		serverUrl: serverUrl,
	}
}

func (s *service) SendEvent(event, computationId, computationKey, status string, details json.RawMessage) error {
	body := Event{
		EventType:     event,
		Timestamp:     time.Now(),
		ComputationID: computationId,
		Originator:    s.service,
		Status:        status,
		Details:       details,
	}

	headers := make(map[string]string)
	headers["Content-Type"] = "application/json"
	headers["Authorization"] = computationKey

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return s.SendRaw(jsonBody, headers)
}

func (s *service) SendRaw(body []byte, headers map[string]string) error {
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/computations/events", s.serverUrl), bytes.NewReader(body))
	if err != nil {
		return err
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	if res.StatusCode != http.StatusCreated {
		return errFailedToCreateNotification
	}
	return nil
}
