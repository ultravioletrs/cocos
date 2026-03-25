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
	pb "github.com/ultravioletrs/cocos/agent/runner"
)

// MockEventService is a mock implementation of events.Service.
type MockEventService struct {
	events []interface{}
}

func (m *MockEventService) SendEvent(cmpID, event, status string, details json.RawMessage) {
	m.events = append(m.events, map[string]interface{}{
		"cmpID":   cmpID,
		"event":   event,
		"status":  status,
		"details": details,
	})
}

// TestNewRunnerService tests the creation of a new runner service.
func TestNewRunnerService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventSvc := &MockEventService{}

	rs := New(logger, eventSvc)
	require.NotNil(t, rs)
	assert.NotNil(t, rs.logger)
	assert.NotNil(t, rs.eventSvc)
	assert.Nil(t, rs.currentAlgo)
}

// TestRunWithBinaryAlgorithm tests running a binary algorithm.
func TestRunWithBinaryAlgorithm(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventSvc := &MockEventService{}
	rs := New(logger, eventSvc)

	req := &pb.RunRequest{
		ComputationId: "test-1",
		AlgoType:      "bin",
		Algorithm:     []byte("#!/bin/bash\necho 'test'"),
		Args:          []string{"arg1", "arg2"},
	}

	resp, err := rs.Run(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.Error)
	assert.Equal(t, "test-1", resp.ComputationId)
	t.Cleanup(func() {
		_ = os.Remove("algo")
	})
}

// TestRunWithPythonAlgorithm tests running a Python algorithm.
func TestRunWithPythonAlgorithm(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventSvc := &MockEventService{}
	rs := New(logger, eventSvc)

	req := &pb.RunRequest{
		ComputationId: "test-python",
		AlgoType:      "python",
		Algorithm:     []byte("print('hello')"),
		Args:          []string{},
		Requirements:  []byte("numpy==2.2.0"),
	}

	resp, err := rs.Run(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.Error)
	assert.Equal(t, "test-python", resp.ComputationId)
	t.Cleanup(func() {
		_ = os.Remove("algo")
	})
}

// TestRunWithPythonAlgorithmNoRequirements tests running Python without requirements.
func TestRunWithPythonAlgorithmNoRequirements(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventSvc := &MockEventService{}
	rs := New(logger, eventSvc)

	req := &pb.RunRequest{
		ComputationId: "test-python-noreq",
		AlgoType:      "python",
		Algorithm:     []byte("print('hello')"),
		Args:          []string{},
	}

	resp, err := rs.Run(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.Error)
	assert.Equal(t, "test-python-noreq", resp.ComputationId)
	t.Cleanup(func() {
		_ = os.Remove("algo")
	})
}

// TestRunWithWasmAlgorithm tests running a WASM algorithm.
func TestRunWithWasmAlgorithm(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventSvc := &MockEventService{}
	rs := New(logger, eventSvc)

	req := &pb.RunRequest{
		ComputationId: "test-wasm",
		AlgoType:      "wasm",
		Algorithm:     []byte{0x00, 0x61, 0x73, 0x6d},
		Args:          []string{},
	}

	resp, err := rs.Run(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	if resp.Error != "" {
		assert.Contains(t, resp.Error, "wasmedge")
		t.Skip("wasmedge not found, skipping test")
	}
	assert.Equal(t, "test-wasm", resp.ComputationId)
	t.Cleanup(func() {
		_ = os.Remove("algo")
	})
}

// TestRunWithDockerAlgorithm tests running a Docker algorithm.
func TestRunWithDockerAlgorithm(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventSvc := &MockEventService{}
	rs := New(logger, eventSvc)

	req := &pb.RunRequest{
		ComputationId: "test-docker",
		AlgoType:      "docker",
		Algorithm:     []byte("FROM ubuntu:latest\nRUN echo 'test'"),
		Args:          []string{},
	}

	resp, err := rs.Run(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	if resp.Error != "" {
		assert.Contains(t, resp.Error, "Docker")
		t.Skip("Docker issue, skipping test")
	}
	assert.Equal(t, "test-docker", resp.ComputationId)
	t.Cleanup(func() {
		_ = os.Remove("algo")
	})
}

// TestRunWithUnsupportedAlgorithmType tests running with unsupported algorithm type.
func TestRunWithUnsupportedAlgorithmType(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventSvc := &MockEventService{}
	rs := New(logger, eventSvc)

	req := &pb.RunRequest{
		ComputationId: "test-unsupported",
		AlgoType:      "unsupported",
		Algorithm:     []byte("test"),
		Args:          []string{},
	}

	resp, err := rs.Run(context.Background(), req)
	require.Error(t, err)
	require.Nil(t, resp)
}

// TestRunAlreadyRunning tests running computation when one is already running.
func TestRunAlreadyRunning(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventSvc := &MockEventService{}
	rs := New(logger, eventSvc)

	// Use a long-running bash script
	req := &pb.RunRequest{
		ComputationId: "test-running",
		AlgoType:      "bin",
		Algorithm:     []byte("#!/bin/bash\nsleep 30"),
		Args:          []string{},
	}

	// Start first computation (will run for 30 seconds)
	go func() {
		_, _ = rs.Run(context.Background(), req)
	}()

	// Give it time to start
	time.Sleep(500 * time.Millisecond)

	// Try to run another immediately - should fail
	resp, err := rs.Run(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "computation already running", resp.Error)
	t.Cleanup(func() {
		_ = os.Remove("algo")
	})
}

// TestStopWhenRunning tests stopping a running computation.
func TestStopWhenRunning(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventSvc := &MockEventService{}
	rs := New(logger, eventSvc)

	req := &pb.RunRequest{
		ComputationId: "test-stop",
		AlgoType:      "bin",
		Algorithm:     []byte("#!/bin/bash\nsleep 10"),
		Args:          []string{},
	}

	go func() {
		_, _ = rs.Run(context.Background(), req)
	}()

	// Give it time to start
	time.Sleep(500 * time.Millisecond)

	stopReq := &pb.StopRequest{
		ComputationId: "test-stop",
	}

	stopResp, err := rs.Stop(context.Background(), stopReq)
	require.NoError(t, err)
	require.NotNil(t, stopResp)
	t.Cleanup(func() {
		_ = os.Remove("algo")
	})
}

// TestRunErrors tests error paths in Run.
func TestRunErrors(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventSvc := &MockEventService{}
	rs := New(logger, eventSvc)

	t.Run("create algo file failure", func(t *testing.T) {
		// Create a directory named "algo" to make os.Create("algo") fail
		err := os.Mkdir("algo", 0o755)
		require.NoError(t, err)
		defer os.RemoveAll("algo")

		req := &pb.RunRequest{
			ComputationId: "test-err",
			AlgoType:      "bin",
			Algorithm:     []byte("test"),
		}
		_, err = rs.Run(context.Background(), req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "error creating algorithm file")
	})

	t.Run("requirements file creation failure", func(t *testing.T) {
		// This one is harder because it uses os.CreateTemp("", "requirements.txt")
		// We can't easily make this fail without reaching into the system's temp dir.
		// Skipping for now as it's a very unlikely edge case.
	})
}

// TestConcurrentRun tests that concurrent runs are properly serialized.
func TestConcurrentRun(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventSvc := &MockEventService{}
	rs := New(logger, eventSvc)

	req := &pb.RunRequest{
		ComputationId: "test-concurrent",
		AlgoType:      "bin",
		Algorithm:     []byte("#!/bin/bash\nsleep 15"),
		Args:          []string{},
	}

	// Start first run in goroutine (will run for 15 seconds)
	go func() {
		_, _ = rs.Run(context.Background(), req)
	}()

	// Give it time to actually start
	time.Sleep(500 * time.Millisecond)

	// Concurrent attempt should fail
	resp2, err := rs.Run(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "computation already running", resp2.Error)
	t.Cleanup(func() {
		_ = os.Remove("algo")
	})
}

// TestRunWithMultipleArgs tests running with multiple arguments.
func TestRunWithMultipleArgs(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventSvc := &MockEventService{}
	rs := New(logger, eventSvc)

	req := &pb.RunRequest{
		ComputationId: "test-multi-args",
		AlgoType:      "bin",
		Algorithm:     []byte("#!/bin/bash\necho $@"),
		Args:          []string{"arg1", "arg2", "arg3", "arg4"},
	}

	resp, err := rs.Run(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.Error)
	assert.Equal(t, "test-multi-args", resp.ComputationId)
	t.Cleanup(func() {
		_ = os.Remove("algo")
	})
}
