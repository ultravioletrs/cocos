// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package events

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

type mockConn struct {
	writeErr error
	buf      bytes.Buffer
}

func (m *mockConn) Write(p []byte) (n int, err error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	return m.buf.Write(p)
}

func TestSendEventSuccess(t *testing.T) {
	mockConnection := &mockConn{}

	svc, err := New("test_service", "12345", mockConnection)
	assert.NoError(t, err)

	details := json.RawMessage(`{"key": "value"}`)

	err = svc.SendEvent("test_event", "success", details)
	assert.NoError(t, err)

	var writtenMessage EventsLogs
	err = proto.Unmarshal(mockConnection.buf.Bytes(), &writtenMessage)
	assert.NoError(t, err)

	assert.Equal(t, "test_event", writtenMessage.GetAgentEvent().EventType)
	assert.Equal(t, "12345", writtenMessage.GetAgentEvent().ComputationId)
	assert.Equal(t, "test_service", writtenMessage.GetAgentEvent().Originator)
	assert.Equal(t, "success", writtenMessage.GetAgentEvent().Status)

	now := time.Now()
	eventTimestamp := writtenMessage.GetAgentEvent().GetTimestamp().AsTime()
	assert.WithinDuration(t, now, eventTimestamp, 1*time.Second)
}

func TestSendEventFailure(t *testing.T) {
	mockConnection := &mockConn{writeErr: errors.New("write error")}

	svc, err := New("test_service", "12345", mockConnection)
	assert.NoError(t, err)

	details := json.RawMessage(`{"key": "value"}`)

	err = svc.SendEvent("test_event", "failure", details)
	assert.Error(t, err)
	assert.Equal(t, "write error", err.Error())

	assert.Len(t, svc.(*service).cachedMessages, 1)
}

func TestClose(t *testing.T) {
	mockConnection := &mockConn{}

	svc, err := New("test_service", "12345", mockConnection)
	assert.NoError(t, err)

	svc.Close()

	time.Sleep(1 * time.Second)

	details := json.RawMessage(`{"key": "value"}`)
	err = svc.SendEvent("test_event", "success", details)
	assert.NoError(t, err)
}
