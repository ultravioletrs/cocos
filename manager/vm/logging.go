// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package vm

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"strings"

	"github.com/ultravioletrs/cocos/pkg/manager"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	_                      io.Writer = &Stdout{}
	_                      io.Writer = &Stderr{}
	ErrFailedToSendMessage           = errors.New("failed to send message to channel")
	ErrPanicRecovered                = errors.New("panic recovered: channel may be closed")
)

const bufSize = 1024

type Stdout struct {
	LogsChan      chan *manager.ClientStreamMessage
	ComputationId string
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
func (s *Stdout) Write(p []byte) (n int, err error) {
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

		if err := sendLog(s.LogsChan, s.ComputationId, string(buf[:n]), slog.LevelDebug.String()); err != nil {
			return len(p) - inBuf.Len(), err
		}
	}

	return len(p), nil
}

type Stderr struct {
	LogsChan      chan *manager.ClientStreamMessage
	ComputationId string
	StateMachine  StateMachine
}

// Write implements io.Writer.
func (s *Stderr) Write(p []byte) (n int, err error) {
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

		if err := sendLog(s.LogsChan, s.ComputationId, string(buf[:n]), ""); err != nil {
			return len(p) - inBuf.Len(), err
		}
	}

	// Ensure vm-provision failure message is sent
	eventMsg := &manager.ClientStreamMessage{
		Message: &manager.ClientStreamMessage_AgentEvent{
			AgentEvent: &manager.AgentEvent{
				ComputationId: s.ComputationId,
				EventType:     s.StateMachine.State(),
				Timestamp:     timestamppb.Now(),
				Originator:    "manager",
				Status:        manager.Warning.String(),
			},
		},
	}

	if err := safeSend(s.LogsChan, eventMsg); err != nil {
		return len(p), err
	}

	return len(p), nil
}

func sendLog(logsChan chan *manager.ClientStreamMessage, computationID, message, level string) error {
	if len(message) < 3 {
		return nil
	}

	if level == "" {
		if strings.Contains(strings.ToLower(message), "warning") {
			level = slog.LevelWarn.String()
		} else {
			level = slog.LevelError.String()
		}
	}

	msg := &manager.ClientStreamMessage{
		Message: &manager.ClientStreamMessage_AgentLog{
			AgentLog: &manager.AgentLog{
				Message:       message,
				ComputationId: computationID,
				Level:         level,
				Timestamp:     timestamppb.Now(),
			},
		},
	}

	if err := safeSend(logsChan, msg); err != nil {
		return err
	}

	return nil
}
