// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package vm

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"strings"

	pkgmanager "github.com/ultravioletrs/cocos/pkg/manager"
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
	EventSender   EventSender
	ComputationId string
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

		if err := sendLog(s.EventSender, s.ComputationId, string(buf[:n]), slog.LevelDebug.String()); err != nil {
			return len(p) - inBuf.Len(), err
		}
	}

	return len(p), nil
}

type Stderr struct {
	EventSender   EventSender
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

		if err := sendLog(s.EventSender, s.ComputationId, string(buf[:n]), ""); err != nil {
			return len(p) - inBuf.Len(), err
		}
	}

	eventMsg := &Event{
		ComputationId: s.ComputationId,
		EventType:     s.StateMachine.State(),
		Timestamp:     timestamppb.Now(),
		Originator:    "manager",
		Status:        pkgmanager.Warning.String(),
	}

	s.EventSender(eventMsg)

	return len(p), nil
}

func sendLog(eventSender EventSender, computationID, message, level string) error {
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

	msg := Log{
		Message:       message,
		ComputationId: computationID,
		Level:         level,
		Timestamp:     timestamppb.Now(),
	}

	eventSender(&msg)

	return nil
}
