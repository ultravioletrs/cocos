// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package runner

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	pb "github.com/ultravioletrs/cocos/agent/runner"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

// mockComputationRunnerServer is a mock implementation of the ComputationRunnerServer.
type mockComputationRunnerServer struct {
	pb.UnimplementedComputationRunnerServer
	runCalled  bool
	stopCalled bool
	runErr     error
	stopErr    error
}

func (m *mockComputationRunnerServer) Run(ctx context.Context, req *pb.RunRequest) (*pb.RunResponse, error) {
	m.runCalled = true
	if m.runErr != nil {
		return nil, m.runErr
	}
	return &pb.RunResponse{
		ComputationId: req.ComputationId,
		Error:         "",
	}, nil
}

func (m *mockComputationRunnerServer) Stop(ctx context.Context, req *pb.StopRequest) (*emptypb.Empty, error) {
	m.stopCalled = true
	if m.stopErr != nil {
		return nil, m.stopErr
	}
	return &emptypb.Empty{}, nil
}

// TestNewClient tests creating a new gRPC client.
func TestNewClient(t *testing.T) {
	// Create a temporary directory for the socket
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	// Start a mock gRPC server
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockComputationRunnerServer{}
	pb.RegisterComputationRunnerServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Create client
	client, err := NewClient(socketPath)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Clean up
	err = client.Close()
	assert.NoError(t, err)
}

// TestNewClientInvalidSocket tests creating a client with invalid socket path.
func TestNewClientInvalidSocket(t *testing.T) {
	// Use a non-existent socket path
	socketPath := "/tmp/nonexistent-" + time.Now().Format("20060102150405") + ".sock"

	// Create client - this should succeed as grpc.NewClient is lazy
	client, err := NewClient(socketPath)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Close should work even if never connected
	err = client.Close()
	assert.NoError(t, err)
}

// TestClientRun tests the Run method.
func TestClientRun(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test-run.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockComputationRunnerServer{}
	pb.RegisterComputationRunnerServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	// Call Run
	ctx := context.Background()
	req := &pb.RunRequest{
		ComputationId: "test-computation",
	}

	resp, err := client.Run(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "test-computation", resp.ComputationId)
	assert.True(t, mockServer.runCalled)
}

// TestClientRunWithCanceledContext tests Run with a canceled context.
func TestClientRunWithCanceledContext(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test-run-cancel.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockComputationRunnerServer{}
	pb.RegisterComputationRunnerServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	// Create a canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req := &pb.RunRequest{
		ComputationId: "test-computation",
	}

	_, err = client.Run(ctx, req)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")
}

// TestClientStop tests the Stop method.
func TestClientStop(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test-stop.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockComputationRunnerServer{}
	pb.RegisterComputationRunnerServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	// Call Stop
	ctx := context.Background()
	req := &pb.StopRequest{
		ComputationId: "test-computation",
	}

	resp, err := client.Stop(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, mockServer.stopCalled)
}

// TestClientStopWithTimeout tests Stop with context timeout.
func TestClientStopWithTimeout(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test-stop-timeout.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockComputationRunnerServer{}
	pb.RegisterComputationRunnerServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)
	defer client.Close()

	// Create a context that will timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := &pb.StopRequest{
		ComputationId: "test-computation",
	}

	// Stop should complete within the timeout
	resp, err := client.Stop(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, mockServer.stopCalled)
}

// TestClientClose tests the Close method.
func TestClientClose(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test-close.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockComputationRunnerServer{}
	pb.RegisterComputationRunnerServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)

	// Close should succeed
	err = client.Close()
	assert.NoError(t, err)
}

// TestClientOperationsAfterClose tests that operations fail gracefully after close.
func TestClientOperationsAfterClose(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test-after-close.sock")

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockComputationRunnerServer{}
	pb.RegisterComputationRunnerServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(socketPath)
	require.NoError(t, err)

	// Close the client
	err = client.Close()
	require.NoError(t, err)

	// Try to use the client after closing
	ctx := context.Background()
	runReq := &pb.RunRequest{ComputationId: "test"}

	// This should fail because connection is closed
	_, err = client.Run(ctx, runReq)
	assert.Error(t, err)
}

// TestNewClientWithRelativePath tests creating client with relative socket path.
func TestNewClientWithRelativePath(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()

	// Change to temp directory
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer func() {
		err := os.Chdir(oldWd)
		require.NoError(t, err)
	}()

	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	socketPath := "relative-test.sock"

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	defer listener.Close()

	grpcServer := grpc.NewServer()
	mockServer := &mockComputationRunnerServer{}
	pb.RegisterComputationRunnerServer(grpcServer, mockServer)

	go func() {
		_ = grpcServer.Serve(listener)
	}()
	defer grpcServer.Stop()

	time.Sleep(100 * time.Millisecond)

	// Create client with relative path
	client, err := NewClient(socketPath)
	require.NoError(t, err)
	require.NotNil(t, client)

	err = client.Close()
	assert.NoError(t, err)
}
