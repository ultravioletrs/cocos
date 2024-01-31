// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agentevents

import (
	"context"
	"net"

	"github.com/mdlayher/vsock"
	"github.com/ultravioletrs/cocos/internal/events"
)

const (
	VsockEventsPort uint32 = 9998
	svc             string = "agent"
	messageSize     int    = 1024
)

type service struct {
	svc            events.Service
	listener       *vsock.Listener
	computationKey string
}

type Service interface {
	Forward(ctx context.Context, errChan chan<- error)
}

func New(eventServerUrl, compKey string) (Service, error) {
	l, err := vsock.Listen(VsockEventsPort, nil)
	if err != nil {
		return nil, err
	}
	return &service{
		svc:            events.New(svc, eventServerUrl),
		listener:       l,
		computationKey: compKey,
	}, nil
}

func (s *service) Forward(ctx context.Context, errChan chan<- error) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			errChan <- err
			continue
		}
		go s.handleConnections(conn, errChan)
	}
}

func (s *service) handleConnections(conn net.Conn, errCh chan<- error) {
	defer conn.Close()
	for {
		b := make([]byte, messageSize)
		n, err := conn.Read(b)
		if err != nil {
			errCh <- err
			return
		}

		headers := map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer " + s.computationKey,
		}

		if err := s.svc.SendRaw(b[:n], headers); err != nil {
			errCh <- err
			return
		}
	}
}
