// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/ultravioletrs/cocos/pkg/manager"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	errFailedToParseCID    = fmt.Errorf("failed to parse computation ID")
	errComputationNotFound = fmt.Errorf("computation not found")
)

func (ms *managerService) computationIDFromAddress(address string) (string, error) {
	re := regexp.MustCompile(`vm\((\d+)\)`)
	matches := re.FindStringSubmatch(address)

	if len(matches) > 1 {
		cid, err := strconv.Atoi(matches[1])
		if err != nil {
			return "", err
		}
		return ms.findComputationID(cid)
	}
	return "", errFailedToParseCID
}

func (ms *managerService) findComputationID(cid int) (string, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	for cmpID, vm := range ms.vms {
		if vm.GetCID() == cid {
			return cmpID, nil
		}
	}

	return "", errComputationNotFound
}

func (ms *managerService) reportBrokenConnection(cmpID string) {
	ms.eventsChan <- &ClientStreamMessage{
		Message: &ClientStreamMessage_AgentEvent{
			AgentEvent: &AgentEvent{
				EventType:     ms.vms[cmpID].State(),
				ComputationId: cmpID,
				Status:        manager.Disconnected.String(),
				Timestamp:     timestamppb.Now(),
				Originator:    "manager",
			},
		},
	}
}

func (ms *managerService) ReportBrokenConnection(addr string) {
	cmpID, err := ms.computationIDFromAddress(addr)
	if err != nil {
		ms.logger.Warn(err.Error())
		return
	}
	ms.reportBrokenConnection(cmpID)
}
