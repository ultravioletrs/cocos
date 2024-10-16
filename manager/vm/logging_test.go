// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package vm

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	pkgmanager "github.com/ultravioletrs/cocos/pkg/manager"
)

func TestStdoutWrite(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedWrites int
	}{
		{
			name:           "Single write within buffer size",
			input:          "Hello, World!",
			expectedWrites: 1,
		},
		{
			name:           "Multiple writes within buffer size",
			input:          "This is a longer message that will be split into multiple writes.",
			expectedWrites: 1,
		},
		{
			name:           "Large write exceeding buffer size",
			input:          string(make([]byte, bufSize*2+3)),
			expectedWrites: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventLogChan := make(chan EventsLogs, 10)
			s := &Stdout{
				EventSender: func(event EventsLogs) {
					eventLogChan <- event
				},
				ComputationId: "test-computation",
			}

			n, err := s.Write([]byte(tt.input))

			assert.NoError(t, err)
			assert.Equal(t, len(tt.input), n)

			var receivedWrites int
			for i := 0; i < tt.expectedWrites; i++ {
				select {
				case msg := <-eventLogChan:
					receivedWrites++
					agentLog := msg.(*Log)
					assert.NotNil(t, agentLog)
					assert.Equal(t, "test-computation", agentLog.ComputationId)
					assert.Equal(t, slog.LevelDebug.String(), agentLog.Level)
					assert.NotEmpty(t, agentLog.Message)
					assert.NotNil(t, agentLog.Timestamp)
				case <-time.After(time.Second):
					t.Fatal("Timed out waiting for log message")
				}
			}

			assert.Equal(t, tt.expectedWrites, receivedWrites)
		})
	}
}

func TestStderrWrite(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedWrites int
	}{
		{
			name:           "Single write within buffer size",
			input:          "Error: Something went wrong",
			expectedWrites: 1,
		},
		{
			name:           "Multiple writes within buffer size",
			input:          "This is a longer error message that will be split into multiple writes.",
			expectedWrites: 1,
		},
		{
			name:           "Large write exceeding buffer size",
			input:          string(make([]byte, bufSize*2)),
			expectedWrites: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventLogChan := make(chan EventsLogs, 10)
			s := &Stderr{
				EventSender: func(event EventsLogs) {
					eventLogChan <- event
				},
				ComputationId: "test-computation",
				StateMachine:  NewStateMachine(),
			}

			err := s.StateMachine.Transition(pkgmanager.VmRunning)
			assert.NoError(t, err)

			n, err := s.Write([]byte(tt.input))

			assert.NoError(t, err)
			assert.Equal(t, len(tt.input), n)

			var receivedWrites int
			for i := 0; i < tt.expectedWrites; i++ {
				select {
				case msg := <-eventLogChan:
					receivedWrites++
					switch logEv := msg.(type) {
					case *Log:
						assert.NotNil(t, logEv)
						assert.Equal(t, "test-computation", logEv.ComputationId)
						assert.Equal(t, slog.LevelError.String(), logEv.Level)
						assert.NotEmpty(t, logEv.Message)
						assert.NotNil(t, logEv.Timestamp)
					case *Event:
						assert.NotNil(t, logEv)
						assert.Equal(t, "test-computation", logEv.ComputationId)
						assert.Equal(t, pkgmanager.VmRunning.String(), logEv.EventType)
						assert.Equal(t, pkgmanager.Warning.String(), logEv.Status)
						assert.NotNil(t, logEv.Timestamp)
					}
				case <-time.After(time.Second):
					t.Fatal("Timed out waiting for log message")
				}
			}

			assert.Equal(t, tt.expectedWrites, receivedWrites)
		})
	}
}

func TestStdoutWriteErrorHandling(t *testing.T) {
	eventLogChan := make(chan EventsLogs, 10)
	s := &Stdout{
		EventSender: func(event EventsLogs) {
			eventLogChan <- event
		},
		ComputationId: "test-computation",
	}

	// Test with a closed channel to simulate an error condition
	close(eventLogChan)

	message := []byte("This should fail")
	n, err := s.Write(message)

	assert.Error(t, err)
	assert.Equal(t, len(message), n)
	assert.Equal(t, ErrPanicRecovered, err)
}

func TestStderrWriteErrorHandling(t *testing.T) {
	eventLogChan := make(chan EventsLogs, 10)
	s := &Stderr{
		EventSender: func(event EventsLogs) {
			eventLogChan <- event
		},
		ComputationId: "test-computation",
	}

	// Test with a closed channel to simulate an error condition
	close(eventLogChan)

	message := []byte("This should fail")
	n, err := s.Write(message)

	assert.Error(t, err)
	assert.Equal(t, len(message), n)
	assert.Equal(t, ErrPanicRecovered, err)
}
