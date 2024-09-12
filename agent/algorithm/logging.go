// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package algorithm

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

const bufSize = 1024

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

	if err := s.EventSvc.SendEvent("algorithm-run", "error", json.RawMessage{}); err != nil {
		return len(p), err
	}

	return len(p), nil
}
