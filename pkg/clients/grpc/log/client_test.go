// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package log

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/agent/log"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// mockLogCollectorServer is a mock implementation of the LogCollectorServer.
type mockLogCollectorServer struct {
	log.UnimplementedLogCollectorServer
	sendLogCalled   bool
	sendEventCalled bool
	lastLogEntry    *log.LogEntry
	lastEventEntry  *log.EventEntry
	sendLogErr      error
	sendEventErr    error
}

func (m *mockLogCollectorServer) SendLog(ctx context.Context, entry *log.LogEntry) (*emptypb.Empty, error) {
	m.sendLogCalled = true
	m.lastLogEntry = entry
	if m.sendLogErr != nil {
		return nil, m.sendLogErr
	}
	return &emptypb.Empty{}, nil
}

func (m *mockLogCollectorServer) SendEvent(ctx context.Context, entry *log.EventEntry) (*emptypb.Empty, error) {
	m.sendEventCalled = true
	m.lastEventEntry = entry
	if m.sendEventErr != nil {
		return nil, m.sendEventErr
	}
	return &emptypb.Empty{}, nil
}

// TestNewClient tests creating a new log client.
func TestNewClient(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "log-test.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockLogCollectorServer{}
	log.RegisterLogCollectorServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	require.NotNil(t, client)

	err = client.Close()
	assert.NoError(t, err)
}

// TestClientSendLog tests sending a log entry.
func TestClientSendLog(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "log-sendlog.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockLogCollectorServer{}
	log.RegisterLogCollectorServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	entry := &log.LogEntry{
		Level:         "INFO",
		Message:       "test log message",
		ComputationId: "test-computation",
	}

	err = client.SendLog(ctx, entry)
	require.NoError(t, err)
	assert.True(t, mockServer.sendLogCalled)
	assert.Equal(t, "INFO", mockServer.lastLogEntry.Level)
	assert.Equal(t, "test log message", mockServer.lastLogEntry.Message)
	assert.Equal(t, "test-computation", mockServer.lastLogEntry.ComputationId)
	assert.NotNil(t, mockServer.lastLogEntry.Timestamp)
}

// TestClientSendLogWithTimestamp tests sending a log entry with existing timestamp.
func TestClientSendLogWithTimestamp(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "log-timestamp.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockLogCollectorServer{}
	log.RegisterLogCollectorServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	customTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	entry := &log.LogEntry{
		Level:         "ERROR",
		Message:       "test error",
		ComputationId: "test",
		Timestamp:     timestamppb.New(customTime),
	}

	err = client.SendLog(ctx, entry)
	require.NoError(t, err)
	assert.True(t, mockServer.sendLogCalled)
	assert.Equal(t, customTime.Unix(), mockServer.lastLogEntry.Timestamp.AsTime().Unix())
}

// TestClientSendEvent tests sending an event entry.
func TestClientSendEvent(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "log-sendevent.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockLogCollectorServer{}
	log.RegisterLogCollectorServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	entry := &log.EventEntry{
		EventType:     "computation.started",
		ComputationId: "test-computation",
		Originator:    "agent",
		Status:        "started",
	}

	err = client.SendEvent(ctx, entry)
	require.NoError(t, err)
	assert.True(t, mockServer.sendEventCalled)
	assert.Equal(t, "computation.started", mockServer.lastEventEntry.EventType)
	assert.Equal(t, "agent", mockServer.lastEventEntry.Originator)
	assert.NotNil(t, mockServer.lastEventEntry.Timestamp)
}

// TestClientSendEventWithTimestamp tests sending an event with existing timestamp.
func TestClientSendEventWithTimestamp(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "log-event-timestamp.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockLogCollectorServer{}
	log.RegisterLogCollectorServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx := context.Background()
	customTime := time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC)
	entry := &log.EventEntry{
		EventType:     "test.event",
		ComputationId: "test",
		Timestamp:     timestamppb.New(customTime),
	}

	err = client.SendEvent(ctx, entry)
	require.NoError(t, err)
	assert.True(t, mockServer.sendEventCalled)
	assert.Equal(t, customTime.Unix(), mockServer.lastEventEntry.Timestamp.AsTime().Unix())
}

// TestClientSendLogWithCanceledContext tests SendLog with canceled context.
func TestClientSendLogWithCanceledContext(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "log-cancel.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockLogCollectorServer{}
	log.RegisterLogCollectorServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	entry := &log.LogEntry{
		Level:   "INFO",
		Message: "test",
	}

	err = client.SendLog(ctx, entry)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

// TestClientClose tests closing the client.
func TestClientClose(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "log-close.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockLogCollectorServer{}
	log.RegisterLogCollectorServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)

	err = client.Close()
	assert.NoError(t, err)
}

// TestClientOperationsAfterClose tests operations after closing.
func TestClientOperationsAfterClose(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "log-after-close.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockLogCollectorServer{}
	log.RegisterLogCollectorServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)

	err = client.Close()
	require.NoError(t, err)

	ctx := context.Background()
	entry := &log.LogEntry{
		Level:   "INFO",
		Message: "test",
	}

	err = client.SendLog(ctx, entry)
	assert.Error(t, err)
}
