// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"context"
	"net"
	"regexp"
	"strconv"
)

const (
	VsockEventsPort uint32 = 9998
	svc             string = "agent"
	messageSize     int    = 1024
)

type AgenteventService interface {
	Forward(ctx context.Context, errChan chan<- error)
}

func (ms *managerService) forward() {
	for {
		conn, err := ms.listener.Accept()
		if err != nil {
			ms.logger.Warn(err.Error())
			continue
		}
		go ms.handleForwardConnections(conn)
	}
}

func (ms *managerService) handleForwardConnections(conn net.Conn) {
	defer conn.Close()
	for {
		b := make([]byte, messageSize)
		n, err := conn.Read(b)
		if err != nil {
			ms.logger.Warn(err.Error())
			return
		}

		if err != nil {
			ms.logger.Warn(err.Error())
			return
		}

		cid, err := ms.guestCIDFromAddress(conn.RemoteAddr().String())
		if err != nil {
			ms.logger.Warn(err.Error())
			return
		}

		headers := map[string]string{
			"Content-Type":  "application/json",
			"Authorization": "Bearer " + ms.keys[ms.agents[cid]],
		}

		if err := ms.eventSvc.SendRaw(b[:n], headers); err != nil {
			ms.logger.Warn(err.Error())
			return
		}
	}
}

func (ms *managerService) guestCIDFromAddress(address string) (int, error) {
	re := regexp.MustCompile(`vm\((\d+)\)`)
	matches := re.FindStringSubmatch(address)

	if len(matches) > 1 {
		cid, err := strconv.Atoi(matches[1])
		if err != nil {
			return 0, err
		}
		return cid, nil
	}
	return 0, errFailedToParseCID
}
