// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package vm

import (
	"bytes"
	"errors"
	"io"

	"github.com/ultravioletrs/cocos/pkg/manager"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	_                      io.Writer = &stdout{}
	_                      io.Writer = &stderr{}
	ErrFailedToSendMessage           = errors.New("failed to send message to channel")
	ErrPanicRecovered                = errors.New("panic recovered: channel may be closed")
)

const bufSize = 1024

type stdout struct {
	logsChan      chan *manager.ClientStreamMessage
	computationId string
}

// safeSend safely sends a message to the channel and returns an error on failure.
func safeSend(ch chan *manager.ClientStreamMessage, msg *manager.ClientStreamMessage) (err error) {
	defer func() {
		if r := recover(); r != nil {
			// Recover from panic if the channel is closed
			err = ErrPanicRecovered
		}
	}()
	select {
	case ch <- msg:
		return nil
	default:
		// Channel is full or closed
		return ErrFailedToSendMessage
	}
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
			return len(p) - inBuf.Len(), err
		}

		msg := &manager.ClientStreamMessage{
			Message: &manager.ClientStreamMessage_AgentLog{
				AgentLog: &manager.AgentLog{
					Message:       string(buf[:n]),
					ComputationId: s.computationId,
					Level:         "debug",
					Timestamp:     timestamppb.Now(),
				},
			},
		}

		if err := safeSend(s.logsChan, msg); err != nil {
			return len(p) - inBuf.Len(), err
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
			return len(p) - inBuf.Len(), err
		}

		msg := &manager.ClientStreamMessage{
			Message: &manager.ClientStreamMessage_AgentLog{
				AgentLog: &manager.AgentLog{
					Message:       string(buf[:n]),
					ComputationId: s.computationId,
					Level:         "error",
					Timestamp:     timestamppb.Now(),
				},
			},
		}

		if err := safeSend(s.logsChan, msg); err != nil {
			return len(p) - inBuf.Len(), err
		}
	}

	// Ensure vm-provision failure message is sent
	eventMsg := &manager.ClientStreamMessage{
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

	if err := safeSend(s.logsChan, eventMsg); err != nil {
		return len(p), err
	}

	return len(p), nil
}
