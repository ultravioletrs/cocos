// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package vm

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/ultravioletrs/cocos/pkg/manager"
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
			input:          string(make([]byte, bufSize*2+1)),
			expectedWrites: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logsChan := make(chan *manager.ClientStreamMessage, 10)
			s := &stdout{
				logsChan:      logsChan,
				computationId: "test-computation",
			}

			n, err := s.Write([]byte(tt.input))

			assert.NoError(t, err)
			assert.Equal(t, len(tt.input), n)

			var receivedWrites int
			for i := 0; i < tt.expectedWrites; i++ {
				select {
				case msg := <-logsChan:
					receivedWrites++
					agentLog := msg.GetAgentLog()
					assert.NotNil(t, agentLog)
					assert.Equal(t, "test-computation", agentLog.ComputationId)
					assert.Equal(t, "debug", agentLog.Level)
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
			logsChan := make(chan *manager.ClientStreamMessage, 10)
			s := &stderr{
				logsChan:      logsChan,
				computationId: "test-computation",
			}

			n, err := s.Write([]byte(tt.input))

			assert.NoError(t, err)
			assert.Equal(t, len(tt.input), n)

			var receivedWrites int
			for i := 0; i < tt.expectedWrites; i++ {
				select {
				case msg := <-logsChan:
					receivedWrites++
					switch msg.Message.(type) {
					case *manager.ClientStreamMessage_AgentLog:
						agentLog := msg.GetAgentLog()
						assert.NotNil(t, agentLog)
						assert.Equal(t, "test-computation", agentLog.ComputationId)
						assert.Equal(t, "error", agentLog.Level)
						assert.NotEmpty(t, agentLog.Message)
						assert.NotNil(t, agentLog.Timestamp)
					case *manager.ClientStreamMessage_AgentEvent:
						agentEvent := msg.GetAgentEvent()
						assert.NotNil(t, agentEvent)
						assert.Equal(t, "test-computation", agentEvent.ComputationId)
						assert.Equal(t, "vm-provision", agentEvent.EventType)
						assert.Equal(t, "failed", agentEvent.Status)
						assert.NotNil(t, agentEvent.Timestamp)
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
	logsChan := make(chan *manager.ClientStreamMessage, 1)
	s := &stdout{
		logsChan:      logsChan,
		computationId: "test-computation",
	}

	// Test with a closed channel to simulate an error condition
	close(logsChan)

	message := []byte("This should fail")
	n, err := s.Write(message)

	assert.Error(t, err)
	assert.Equal(t, len(message), n)
	assert.Equal(t, ErrPanicRecovered, err)
}

func TestStderrWriteErrorHandling(t *testing.T) {
	logsChan := make(chan *manager.ClientStreamMessage, 1)
	s := &stderr{
		logsChan:      logsChan,
		computationId: "test-computation",
	}

	// Test with a closed channel to simulate an error condition
	close(logsChan)

	message := []byte("This should fail")
	n, err := s.Write(message)

	assert.Error(t, err)
	assert.Equal(t, len(message), n)
	assert.Equal(t, ErrPanicRecovered, err)
}
