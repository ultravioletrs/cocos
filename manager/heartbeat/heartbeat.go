// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package heartbeat

import (
	"time"

	"github.com/ultravioletrs/cocos/pkg/manager"
)

type Heartbeat struct {
	stream manager.ManagerService_HeartbeatClient
	ticker *time.Ticker
}

func New(stream manager.ManagerService_HeartbeatClient, interval time.Duration) Heartbeat {
	return Heartbeat{
		stream: stream,
		ticker: time.NewTicker(interval),
	}
}

func (h *Heartbeat) Send() error {
	for range h.ticker.C {
		if err := h.stream.Send(&manager.HeartBeatMessage{}); err != nil {
			return err
		}
	}
	return nil
}
