// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package logger

import (
	"context"
	"io"
	"log/slog"

	"github.com/ultravioletrs/cocos/pkg/manager"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var _ slog.Handler = (*handler)(nil)

type handler struct {
	opts  slog.HandlerOptions
	w     io.Writer
	cmpID string
}

func NewProtoHandler(w io.Writer, opts *slog.HandlerOptions, cmpID string) slog.Handler {
	if opts == nil {
		opts = &slog.HandlerOptions{}
	}
	return &handler{
		opts:  *opts,
		w:     w,
		cmpID: cmpID,
	}
}

// Enabled implements slog.Handler.
func (h *handler) Enabled(_ context.Context, l slog.Level) bool {
	minLevel := slog.LevelInfo
	if h.opts.Level != nil {
		minLevel = h.opts.Level.Level()
	}
	return l >= minLevel
}

// Handle implements slog.Handler.
func (h *handler) Handle(_ context.Context, r slog.Record) error {
	message := r.Message
	timestamp := timestamppb.New(r.Time)
	level := r.Level.String()

	// Calculate the number of chunks
	chunkSize := 500
	numChunks := (len(message) + chunkSize - 1) / chunkSize

	for i := 0; i < numChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(message) {
			end = len(message)
		}

		// Create a chunk of the message
		chunk := message[start:end]

		// Create the agent log with the chunk
		agentLog := manager.ClientStreamMessage{
			Message: &manager.ClientStreamMessage_AgentLog{
				AgentLog: &manager.AgentLog{
					Timestamp:     timestamp,
					Message:       chunk,
					Level:         level,
					ComputationId: h.cmpID,
				},
			},
		}

		// Marshal the chunk to protobuf
		b, err := proto.Marshal(&agentLog)
		if err != nil {
			return err
		}

		// Write the chunk to the writer
		if _, err := h.w.Write(b); err != nil {
			return err
		}
	}

	return nil
}

// WithAttrs implements slog.Handler.
func (*handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	panic("unimplemented")
}

// WithGroup implements slog.Handler.
func (*handler) WithGroup(name string) slog.Handler {
	panic("unimplemented")
}
