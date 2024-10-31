// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package logger

import (
	"context"
	"io"
	"log/slog"

	"github.com/ultravioletrs/cocos/agent/events"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var _ slog.Handler = (*handler)(nil)

type handler struct {
	opts  slog.HandlerOptions
	w     io.Writer
	cmpID string
}

//go:generate mockery --name io.Writer --output ./mocks --filename io_writer.go

func NewProtoHandler(conn io.Writer, opts *slog.HandlerOptions, cmpID string) slog.Handler {
	if opts == nil {
		opts = &slog.HandlerOptions{}
	}
	h := &handler{
		opts:  *opts,
		w:     conn,
		cmpID: cmpID,
	}

	return h
}

func (h *handler) Enabled(_ context.Context, l slog.Level) bool {
	minLevel := slog.LevelInfo
	if h.opts.Level != nil {
		minLevel = h.opts.Level.Level()
	}
	return l >= minLevel
}

func (h *handler) Handle(_ context.Context, r slog.Record) error {
	message := r.Message
	timestamp := timestamppb.New(r.Time)
	level := r.Level.String()

	chunkSize := 500
	numChunks := (len(message) + chunkSize - 1) / chunkSize

	for i := 0; i < numChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(message) {
			end = len(message)
		}

		chunk := message[start:end]

		agentLog := events.EventsLogs{
			Message: &events.EventsLogs_AgentLog{
				AgentLog: &events.AgentLog{
					Timestamp:     timestamp,
					Message:       chunk,
					Level:         level,
					ComputationId: h.cmpID,
				},
			},
		}

		b, err := proto.Marshal(&agentLog)
		if err != nil {
			return err
		}

		_, err = h.w.Write(b)
		if err != nil {
			return err
		}
	}

	return nil
}

func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	panic("unimplemented")
}

func (h *handler) WithGroup(name string) slog.Handler {
	panic("unimplemented")
}

func (h *handler) Close() error {
	return nil
}
