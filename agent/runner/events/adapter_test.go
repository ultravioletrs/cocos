// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package events

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	logpb "github.com/ultravioletrs/cocos/agent/log"
)

const testServiceName = "test-service"

// mockLogClient is a mock implementation of the log client.
type mockLogClient struct {
	mock.Mock
}

func (m *mockLogClient) SendLog(ctx context.Context, entry *logpb.LogEntry) error {
	args := m.Called(ctx, entry)
	return args.Error(0)
}

func (m *mockLogClient) SendEvent(ctx context.Context, entry *logpb.EventEntry) error {
	args := m.Called(ctx, entry)
	return args.Error(0)
}

func (m *mockLogClient) Close() error {
	args := m.Called()
	return args.Error(0)
}

// TestNewAdapter tests creating a new adapter.
func TestNewAdapter(t *testing.T) {
	mockClient := new(mockLogClient)
	svc := testServiceName

	adapter := NewAdapter(mockClient, svc)

	assert.NotNil(t, adapter)
}

// TestSendEvent tests sending an event successfully.
func TestSendEvent(t *testing.T) {
	mockClient := new(mockLogClient)
	svc := testServiceName
	adapter := NewAdapter(mockClient, svc)

	cmpID := "test-computation-id"
	event := "computation.started"
	status := "success"
	details := json.RawMessage(`{"key": "value"}`)

	expectedEntry := &logpb.EventEntry{
		EventType:     event,
		ComputationId: cmpID,
		Details:       details,
		Originator:    svc,
		Status:        status,
	}

	mockClient.On("SendEvent", mock.Anything, expectedEntry).Return(nil)

	adapter.SendEvent(cmpID, event, status, details)

	mockClient.AssertExpectations(t)
	mockClient.AssertCalled(t, "SendEvent", mock.Anything, expectedEntry)
}

// TestSendEventWithError tests sending an event when client returns an error.
func TestSendEventWithError(t *testing.T) {
	mockClient := new(mockLogClient)
	svc := testServiceName
	adapter := NewAdapter(mockClient, svc)

	cmpID := "test-computation-id"
	event := "computation.failed"
	status := "error"
	details := json.RawMessage(`{"error": "something went wrong"}`)

	mockClient.On("SendEvent", mock.Anything, mock.Anything).Return(assert.AnError)

	// This should not panic even when error occurs
	adapter.SendEvent(cmpID, event, status, details)

	mockClient.AssertExpectations(t)
	mockClient.AssertCalled(t, "SendEvent", mock.Anything, mock.Anything)
}

// TestSendEventWithNilDetails tests sending an event with nil details.
func TestSendEventWithNilDetails(t *testing.T) {
	mockClient := new(mockLogClient)
	svc := "runner-service"
	adapter := NewAdapter(mockClient, svc)

	cmpID := "comp-123"
	event := "test.event"
	status := "pending"

	expectedEntry := &logpb.EventEntry{
		EventType:     event,
		ComputationId: cmpID,
		Details:       nil,
		Originator:    svc,
		Status:        status,
	}

	mockClient.On("SendEvent", mock.Anything, expectedEntry).Return(nil)

	adapter.SendEvent(cmpID, event, status, nil)

	mockClient.AssertExpectations(t)
}

// TestSendEventWithEmptyStrings tests sending an event with empty strings.
func TestSendEventWithEmptyStrings(t *testing.T) {
	mockClient := new(mockLogClient)
	svc := testServiceName
	adapter := NewAdapter(mockClient, svc)

	expectedEntry := &logpb.EventEntry{
		EventType:     "",
		ComputationId: "",
		Details:       nil,
		Originator:    svc,
		Status:        "",
	}

	mockClient.On("SendEvent", mock.Anything, expectedEntry).Return(nil)

	adapter.SendEvent("", "", "", nil)

	mockClient.AssertExpectations(t)
}
