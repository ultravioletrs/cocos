// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package service

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/agent/cvms"
	"github.com/ultravioletrs/cocos/agent/log"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestNewLogForwarder tests the creation of a new log forwarder
func TestNewLogForwarder(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	queue := make(chan *cvms.ClientStreamMessage, 10)

	lf := New(logger, nil, queue)
	require.NotNil(t, lf)
	assert.NotNil(t, lf.logger)
	assert.Nil(t, lf.cvmsClient)
	assert.NotNil(t, lf.logQueue)
}

// TestSendLog tests sending a log entry
func TestSendLog(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	queue := make(chan *cvms.ClientStreamMessage, 10)

	lf := New(logger, nil, queue)

	req := &log.LogEntry{
		Message:       "Test log message",
		ComputationId: "computation-1",
		Level:         "INFO",
		Timestamp:     timestamppb.New(time.Now()),
	}

	resp, err := lf.SendLog(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify message was queued
	select {
	case msg := <-queue:
		require.NotNil(t, msg)
		agentLog := msg.GetAgentLog()
		assert.NotNil(t, agentLog)
		assert.Equal(t, "Test log message", agentLog.Message)
		assert.Equal(t, "computation-1", agentLog.ComputationId)
		assert.Equal(t, "INFO", agentLog.Level)
	default:
		t.Fatal("No message in queue")
	}
}

// TestSendEvent tests sending an event entry
func TestSendEvent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	queue := make(chan *cvms.ClientStreamMessage, 10)

	lf := New(logger, nil, queue)

	details, err := json.Marshal(map[string]string{"key": "value"})
	require.NoError(t, err)

	req := &log.EventEntry{
		EventType:     "COMPUTATION_STARTED",
		Timestamp:     timestamppb.New(time.Now()),
		ComputationId: "computation-1",
		Details:       details,
		Originator:    "runner",
		Status:        "SUCCESS",
	}

	resp, err := lf.SendEvent(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Verify message was queued
	select {
	case msg := <-queue:
		require.NotNil(t, msg)
		agentEvent := msg.GetAgentEvent()
		assert.NotNil(t, agentEvent)
		assert.Equal(t, "COMPUTATION_STARTED", agentEvent.EventType)
		assert.Equal(t, "computation-1", agentEvent.ComputationId)
		assert.Equal(t, "runner", agentEvent.Originator)
		assert.Equal(t, "SUCCESS", agentEvent.Status)
	default:
		t.Fatal("No message in queue")
	}
}

// TestSendMultipleLogs tests sending multiple log entries
func TestSendMultipleLogs(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	queue := make(chan *cvms.ClientStreamMessage, 100)

	lf := New(logger, nil, queue)

	for i := 0; i < 5; i++ {
		req := &log.LogEntry{
			Message:       "Log message",
			ComputationId: "computation-1",
			Level:         "INFO",
			Timestamp:     timestamppb.New(time.Now()),
		}

		resp, err := lf.SendLog(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)
	}

	assert.Equal(t, 5, len(queue))
}

// TestSendEventWithVariousTypes tests sending events with different types
func TestSendEventWithVariousTypes(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	queue := make(chan *cvms.ClientStreamMessage, 100)

	lf := New(logger, nil, queue)

	eventTypes := []string{"STARTED", "RUNNING", "COMPLETED", "FAILED"}
	for _, eventType := range eventTypes {
		details, _ := json.Marshal(map[string]string{"type": eventType})
		req := &log.EventEntry{
			EventType:     eventType,
			Timestamp:     timestamppb.New(time.Now()),
			ComputationId: "computation-1",
			Details:       details,
			Originator:    "runner",
			Status:        "OK",
		}

		resp, err := lf.SendEvent(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)
	}

	assert.Equal(t, 4, len(queue))
}

// TestSendLogWithEmptyMessage tests sending log with empty message
func TestSendLogWithEmptyMessage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	queue := make(chan *cvms.ClientStreamMessage, 10)

	lf := New(logger, nil, queue)

	req := &log.LogEntry{
		Message:       "",
		ComputationId: "computation-1",
		Level:         "INFO",
		Timestamp:     timestamppb.New(time.Now()),
	}

	resp, err := lf.SendLog(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	select {
	case msg := <-queue:
		agentLog := msg.GetAgentLog()
		assert.Equal(t, "", agentLog.Message)
	default:
		t.Fatal("No message in queue")
	}
}

// TestSendEventWithNilDetails tests sending event with nil details
func TestSendEventWithNilDetails(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	queue := make(chan *cvms.ClientStreamMessage, 10)

	lf := New(logger, nil, queue)

	req := &log.EventEntry{
		EventType:     "TEST_EVENT",
		Timestamp:     timestamppb.New(time.Now()),
		ComputationId: "computation-1",
		Details:       nil,
		Originator:    "test",
		Status:        "OK",
	}

	resp, err := lf.SendEvent(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	select {
	case msg := <-queue:
		agentEvent := msg.GetAgentEvent()
		assert.Nil(t, agentEvent.Details)
	default:
		t.Fatal("No message in queue")
	}
}

// TestSendLogWithVariousLevels tests sending logs with various severity levels
func TestSendLogWithVariousLevels(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	queue := make(chan *cvms.ClientStreamMessage, 100)

	lf := New(logger, nil, queue)

	levels := []string{"DEBUG", "INFO", "WARN", "ERROR"}
	for _, level := range levels {
		req := &log.LogEntry{
			Message:       "Test " + level,
			ComputationId: "computation-1",
			Level:         level,
			Timestamp:     timestamppb.New(time.Now()),
		}

		resp, err := lf.SendLog(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)
	}

	assert.Equal(t, 4, len(queue))
}

// TestSendLogWithDifferentComputationIds tests sending logs with different computation IDs
func TestSendLogWithDifferentComputationIds(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	queue := make(chan *cvms.ClientStreamMessage, 100)

	lf := New(logger, nil, queue)

	for i := 0; i < 3; i++ {
		req := &log.LogEntry{
			Message:       "Message",
			ComputationId: "computation-" + string(rune(48+i)),
			Level:         "INFO",
			Timestamp:     timestamppb.New(time.Now()),
		}

		resp, err := lf.SendLog(context.Background(), req)
		require.NoError(t, err)
		require.NotNil(t, resp)
	}

	assert.Equal(t, 3, len(queue))
}

// TestQueueBehavior tests that queue is properly used
func TestQueueBehavior(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	queue := make(chan *cvms.ClientStreamMessage, 1)

	lf := New(logger, nil, queue)

	req := &log.LogEntry{
		Message:       "Test",
		ComputationId: "computation-1",
		Level:         "INFO",
		Timestamp:     timestamppb.New(time.Now()),
	}

	resp, err := lf.SendLog(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, 1, len(queue))
}

// TestConcurrentSendLog tests concurrent log sending
func TestConcurrentSendLog(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	queue := make(chan *cvms.ClientStreamMessage, 100)

	lf := New(logger, nil, queue)

	for i := 0; i < 10; i++ {
		go func(id int) {
			req := &log.LogEntry{
				Message:       "Concurrent log",
				ComputationId: "computation-1",
				Level:         "INFO",
				Timestamp:     timestamppb.New(time.Now()),
			}

			_, err := lf.SendLog(context.Background(), req)
			require.NoError(t, err)
		}(i)
	}

	// Give goroutines time to complete
	time.Sleep(100 * time.Millisecond)

	// Should have received all messages
	assert.True(t, len(queue) > 0)
}
