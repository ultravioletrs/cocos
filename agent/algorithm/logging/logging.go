// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package logging

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"

	"github.com/ultravioletrs/cocos/agent/events"
)

var (
	_ io.Writer = &Stdout{}
	_ io.Writer = &Stderr{}
)

const (
	bufSize       = 1024
	algorithmRun  = "AlgorithmRun"
	warningStatus = "Warning"
)

type Stdout struct {
	Logger *slog.Logger
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

		s.Logger.Debug(string(buf[:n]))
	}

	return len(p), nil
}

type Stderr struct {
	Logger   *slog.Logger
	EventSvc events.Service
	CmpID    string
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

		s.Logger.Error(string(buf[:n]))
	}

	s.EventSvc.SendEvent(s.CmpID, algorithmRun, warningStatus, json.RawMessage{})

	return len(p), nil
}
