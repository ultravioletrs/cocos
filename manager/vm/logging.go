// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package vm

import (
	"bytes"
	"io"

	"github.com/ultravioletrs/cocos/pkg/manager"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	_ io.Writer = &stdout{}
	_ io.Writer = &stderr{}
)

const bufSize = 1024

type stdout struct {
	logsChan      chan *manager.ClientStreamMessage
	computationId string
}

// Write implements io.Writer.
func (s *stdout) Write(p []byte) (n int, err error) {
	inBuf := bytes.NewBuffer(p)

	buf := make([]byte, bufSize)

	for {
		n, err := inBuf.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return 0, err
		}

		s.logsChan <- &manager.ClientStreamMessage{
			Message: &manager.ClientStreamMessage_AgentLog{
				AgentLog: &manager.AgentLog{
					Message:       string(buf[:n]),
					ComputationId: s.computationId,
					Level:         "debug",
					Timestamp:     timestamppb.Now(),
				},
			},
		}
	}

	return len(p), nil
}

type stderr struct {
	logsChan      chan *manager.ClientStreamMessage
	computationId string
}

// Write implements io.Writer.
func (s *stderr) Write(p []byte) (n int, err error) {
	inBuf := bytes.NewBuffer(p)

	buf := make([]byte, bufSize)

	for {
		n, err := inBuf.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return 0, err
		}

		s.logsChan <- &manager.ClientStreamMessage{
			Message: &manager.ClientStreamMessage_AgentLog{
				AgentLog: &manager.AgentLog{
					Message:       string(buf[:n]),
					ComputationId: s.computationId,
					Level:         "error",
					Timestamp:     timestamppb.Now(),
				},
			},
		}
	}

	s.logsChan <- &manager.ClientStreamMessage{
		Message: &manager.ClientStreamMessage_AgentEvent{
			AgentEvent: &manager.AgentEvent{
				ComputationId: s.computationId,
				EventType:     "vm-provision",
				Timestamp:     timestamppb.Now(),
				Originator:    "manager",
				Status:        "failed",
			},
		},
	}

	return len(p), nil
}
