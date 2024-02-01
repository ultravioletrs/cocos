// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"fmt"
	"net"
	"regexp"
	"strconv"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/mdlayher/vsock"
)

const (
	VsockLogsPort = 9997
)

var errFailedToParseCID = errors.New("failed to parse cid from remote address")

func (ms *managerService) retrieveAgentLogs() {
	l, err := vsock.Listen(VsockLogsPort, nil)
	if err != nil {
		ms.logger.Warn(err.Error())
		return
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			ms.logger.Warn(err.Error())
			continue
		}

		go ms.handleConnections(conn)
	}
}

func (ms *managerService) handleConnections(conn net.Conn) {
	defer conn.Close()
	for {
		b := make([]byte, messageSize)
		n, err := conn.Read(b)
		if err != nil {
			ms.logger.Warn(err.Error())
			return
		}
		agInfo, err := ms.computationIDFromAddress(conn.RemoteAddr().String())
		if err != nil {
			ms.logger.Warn(err.Error())
			continue
		}
		ms.logger.Info(fmt.Sprintf("Agent Log, Computation ID: %s, Log: %s", agInfo.computationID, string(b[:n])))
	}
}

func (ms *managerService) computationIDFromAddress(address string) (agentInfo, error) {
	re := regexp.MustCompile(`vm\((\d+)\)`)
	matches := re.FindStringSubmatch(address)

	if len(matches) > 1 {
		cid, err := strconv.Atoi(matches[1])
		if err != nil {
			return agentInfo{}, err
		}
		return ms.agents[cid], nil
	}
	return agentInfo{}, errFailedToParseCID
}
