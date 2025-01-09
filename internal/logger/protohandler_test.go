// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package logger

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/ultravioletrs/cocos/agent/cvm"
)

type failedWriter struct{}

func (f *failedWriter) Write(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

// TestNewProtoHandler tests the initialization of the ProtoHandler.
func TestNewProtoHandler(t *testing.T) {
	handler := NewProtoHandler(io.Discard, nil, make(chan *cvm.ClientStreamMessage))

	assert.NotNil(t, handler, "Handler should not be nil")
}

// TestHandleMessageSuccess tests the handling of a message when the write succeeds.
func TestHandleMessageSuccess(t *testing.T) {
	handler := NewProtoHandler(io.Discard, nil, make(chan *cvm.ClientStreamMessage, 1))
	record := slog.Record{
		Time:    time.Now(),
		Message: "Test message",
		Level:   slog.LevelInfo,
	}

	err := handler.Handle(context.Background(), record)

	assert.NoError(t, err, "Handle should not return an error")
}

// TestHandleMessageFailure tests the caching mechanism when the write fails.
func TestHandleMessageFailure(t *testing.T) {
	protohandler := NewProtoHandler(&failedWriter{}, nil, make(chan *cvm.ClientStreamMessage, 1))
	record := slog.Record{
		Time:    time.Now(),
		Message: "Test message",
		Level:   slog.LevelInfo,
	}

	err := protohandler.Handle(context.Background(), record)

	assert.True(t, errors.Contains(err, io.ErrUnexpectedEOF), "Handle should return an error")
}

// TestEnabled tests that the handler enables logging based on level.
func TestEnabled(t *testing.T) {
	handler := NewProtoHandler(io.Discard, nil, make(chan *cvm.ClientStreamMessage, 1))

	assert.True(t, handler.Enabled(context.Background(), slog.LevelInfo), "Logging should be enabled for LevelInfo")
	assert.False(t, handler.Enabled(context.Background(), slog.LevelDebug), "Logging should be disabled for LevelDebug by default")
}

// TestPeriodicRetry stops retry after close.
func TestCloseStopsRetry(t *testing.T) {
	mockWriter := io.Discard

	handler := NewProtoHandler(mockWriter, nil, make(chan *cvm.ClientStreamMessage, 1)).(*handler)

	time.Sleep(2 * time.Second)
	err := handler.Close()

	assert.NoError(t, err, "Close should not return an error")
	time.Sleep(1 * time.Second) // Ensure no retry after close
}
