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
)

type service struct {
	svc      events.Service
	listener *vsock.Listener
}

type Service interface {
	Forward(ctx context.Context, errChan chan<- error)
}

func New(eventServerUrl string) (Service, error) {
	l, err := vsock.Listen(VsockEventsPort, nil)
	if err != nil {
		return nil, err
	}
	return &service{
		svc:      events.New(svc, eventServerUrl),
		listener: l,
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
		b := make([]byte, 1024)
		n, err := conn.Read(b)
		if err != nil {
			errCh <- err
			return
		}
		if err := s.svc.SendRaw(b[:n]); err != nil {
			errCh <- err
			return
		}
	}
}
