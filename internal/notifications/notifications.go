// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package notifications

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

var errFailedToCreateNotification = errors.New("failed to create notification on server")

type service struct {
	service   string
	serverUrl string
}

type Service interface {
	SendNotification(event, computationId string) error
}

func New(svc, serverUrl string) Service {
	return &service{
		service:   svc,
		serverUrl: serverUrl,
	}
}

func (s *service) SendNotification(event, computationId string) error {
	body := struct {
		Event         string
		Timestamp     time.Time
		ComputationId string
	}{
		Event:         event,
		Timestamp:     time.Now(),
		ComputationId: computationId,
	}
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, s.serverUrl, bytes.NewReader(jsonBody))
	if err != nil {
		return err
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
