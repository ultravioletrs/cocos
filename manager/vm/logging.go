// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package vm

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
)

var (
	_ io.Writer = &Stdout{}
	_ io.Writer = &Stderr{}
)

const bufSize = 1024

type Stdout struct {
	StateMachine StateMachine
	Logger       *slog.Logger
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

		args := []any{
			slog.String("state", s.StateMachine.State()),
		}

		s.Logger.Info(string(buf[:n]), args...)
	}

	return len(p), nil
}

type Stderr struct {
	StateMachine StateMachine
	Logger       *slog.Logger
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

		args := []any{
			slog.String("state", s.StateMachine.State()),
		}

		if strings.Contains(string(buf[:n]), "Error") {
			s.Logger.Error(string(buf[:n]), args...)
		} else {
			s.Logger.Warn(string(buf[:n]), args...)
		}
	}

	return len(p), nil
}
