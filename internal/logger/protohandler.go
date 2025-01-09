// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package logger

import (
	"context"
	"io"
	"log/slog"

	"github.com/ultravioletrs/cocos/agent/cvm"
	"github.com/ultravioletrs/cocos/agent/events"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var _ slog.Handler = (*handler)(nil)

type handler struct {
	opts  slog.HandlerOptions
	w     io.Writer
	cmpID string
	queue chan *cvm.ClientStreamMessage
}

func NewProtoHandler(conn io.Writer, opts *slog.HandlerOptions, queue chan *cvm.ClientStreamMessage) slog.Handler {
	if opts == nil {
		opts = &slog.HandlerOptions{}
	}
	h := &handler{
		opts:  *opts,
		w:     conn,
		queue: queue,
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

		h.queue <- &cvm.ClientStreamMessage{
			Message: &cvm.ClientStreamMessage_AgentLog{
				AgentLog: &cvm.AgentLog{
					Timestamp:     timestamp,
					Message:       chunk,
					Level:         level,
					ComputationId: h.cmpID,
				},
			},
		}

		b, err := protojson.Marshal(&agentLog)
		if err != nil {
			return err
		}

		_, err = h.w.Write(b)
		if err != nil {
			return err
		}

		_, err = h.w.Write([]byte("\n"))
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
	h.cmpID = name
	return h
}

func (h *handler) Close() error {
	return nil
}
