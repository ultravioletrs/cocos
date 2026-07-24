// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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

func writeRunnerTestFile(t *testing.T, dir, name string, data []byte, mode os.FileMode) string {
	t.Helper()

	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, data, mode))

	return path
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
	origDir, _ := os.Getwd()
	tmpDir := t.TempDir()
	require.NoError(t, os.Chdir(tmpDir))
	defer func() { require.NoError(t, os.Chdir(origDir)) }()
	algoPath := writeRunnerTestFile(t, tmpDir, "algo", []byte("#!/bin/bash\necho 'test'"), 0o700)

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventSvc := &MockEventService{}
	rs := New(logger, eventSvc)

	req := &pb.RunRequest{
		ComputationId: "test-1",
		AlgoType:      "bin",
		AlgorithmPath: algoPath,
		Args:          []string{"arg1", "arg2"},
	}

	resp, err := rs.Run(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.Error)
	assert.Equal(t, "test-1", resp.ComputationId)
}

// TestRunWithPythonAlgorithm tests running a Python algorithm.
func TestRunWithPythonAlgorithm(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventSvc := &MockEventService{}
	rs := New(logger, eventSvc)
	tmpDir := t.TempDir()
	algoPath := writeRunnerTestFile(t, tmpDir, "algo.py", []byte("print('hello')"), 0o600)
	requirementsPath := writeRunnerTestFile(t, tmpDir, "requirements.txt", []byte("numpy==2.2.0"), 0o600)

	req := &pb.RunRequest{
		ComputationId:    "test-python",
		AlgoType:         "python",
		AlgorithmPath:    algoPath,
		Args:             []string{},
		RequirementsPath: requirementsPath,
	}

	resp, err := rs.Run(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.Error)
	assert.Equal(t, "test-python", resp.ComputationId)
}

// TestRunWithPythonAlgorithmNoRequirements tests running Python without requirements.
func TestRunWithPythonAlgorithmNoRequirements(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventSvc := &MockEventService{}
	rs := New(logger, eventSvc)
	tmpDir := t.TempDir()
	algoPath := writeRunnerTestFile(t, tmpDir, "algo.py", []byte("print('hello')"), 0o600)

	req := &pb.RunRequest{
		ComputationId: "test-python-noreq",
		AlgoType:      "python",
		AlgorithmPath: algoPath,
		Args:          []string{},
	}

	resp, err := rs.Run(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.Error)
	assert.Equal(t, "test-python-noreq", resp.ComputationId)
}

// TestRunWithWasmAlgorithm tests running a WASM algorithm.
func TestRunWithWasmAlgorithm(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventSvc := &MockEventService{}
	rs := New(logger, eventSvc)
	tmpDir := t.TempDir()
	algoPath := writeRunnerTestFile(t, tmpDir, "algo.wasm", []byte{0x00, 0x61, 0x73, 0x6d}, 0o600)

	req := &pb.RunRequest{
		ComputationId: "test-wasm",
		AlgoType:      "wasm",
		AlgorithmPath: algoPath,
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
}

// TestRunWithDockerAlgorithm tests running a Docker algorithm.
func TestRunWithDockerAlgorithm(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventSvc := &MockEventService{}
	rs := New(logger, eventSvc)
	tmpDir := t.TempDir()
	algoPath := writeRunnerTestFile(t, tmpDir, "Dockerfile", []byte("FROM ubuntu:latest\nRUN echo 'test'"), 0o600)

	req := &pb.RunRequest{
		ComputationId: "test-docker",
		AlgoType:      "docker",
		AlgorithmPath: algoPath,
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
}

// TestRunWithUnsupportedAlgorithmType tests running with unsupported algorithm type.
func TestRunWithUnsupportedAlgorithmType(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventSvc := &MockEventService{}
	rs := New(logger, eventSvc)

	req := &pb.RunRequest{
		ComputationId: "test-unsupported",
		AlgoType:      "unsupported",
		AlgorithmPath: "/tmp/test",
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
	tmpDir := t.TempDir()
	algoPath := writeRunnerTestFile(t, tmpDir, "algo", []byte("#!/bin/bash\nsleep 30"), 0o700)

	// Use a long-running bash script
	req := &pb.RunRequest{
		ComputationId: "test-running",
		AlgoType:      "bin",
		AlgorithmPath: algoPath,
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
}

// TestStopWhenRunning tests stopping a running computation.
func TestStopWhenRunning(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventSvc := &MockEventService{}
	rs := New(logger, eventSvc)
	tmpDir := t.TempDir()
	algoPath := writeRunnerTestFile(t, tmpDir, "algo", []byte("#!/bin/bash\nsleep 10"), 0o700)

	req := &pb.RunRequest{
		ComputationId: "test-stop",
		AlgoType:      "bin",
		AlgorithmPath: algoPath,
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
}

// TestRunErrors tests error paths in Run.
func TestRunErrors(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventSvc := &MockEventService{}
	rs := New(logger, eventSvc)

	t.Run("create algo file failure", func(t *testing.T) {
		var err error
		req := &pb.RunRequest{
			ComputationId: "test-err",
			AlgoType:      "bin",
			AlgorithmPath: "",
		}
		_, err = rs.Run(context.Background(), req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "algorithm path is required")
	})

	t.Run("requirements file creation failure", func(t *testing.T) {
		// Requirements are now staged by the agent, so the runner no longer creates temp files.
	})

	t.Run("chmod failure", func(t *testing.T) {
		// Permission management is now the agent's responsibility during staging.
	})

	t.Run("write algorithm failure", func(t *testing.T) {
		// Write failures are now handled by the agent before invoking the runner.
	})
}

// TestConcurrentRun tests that concurrent runs are properly serialized.
func TestConcurrentRun(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventSvc := &MockEventService{}
	rs := New(logger, eventSvc)
	tmpDir := t.TempDir()
	algoPath := writeRunnerTestFile(t, tmpDir, "algo", []byte("#!/bin/bash\nsleep 15"), 0o700)

	req := &pb.RunRequest{
		ComputationId: "test-concurrent",
		AlgoType:      "bin",
		AlgorithmPath: algoPath,
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
}

// TestRunWithMultipleArgs tests running with multiple arguments.
func TestRunWithMultipleArgs(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventSvc := &MockEventService{}
	rs := New(logger, eventSvc)
	tmpDir := t.TempDir()
	algoPath := writeRunnerTestFile(t, tmpDir, "algo", []byte("#!/bin/bash\necho $@"), 0o700)

	req := &pb.RunRequest{
		ComputationId: "test-multi-args",
		AlgoType:      "bin",
		AlgorithmPath: algoPath,
		Args:          []string{"arg1", "arg2", "arg3", "arg4"},
	}

	resp, err := rs.Run(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Empty(t, resp.Error)
	assert.Equal(t, "test-multi-args", resp.ComputationId)
}

func TestStopFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventSvc := &MockEventService{}
	rs := New(logger, eventSvc)

	// Mock an algorithm that fails on Stop
	rs.currentAlgo = &MockAlgorithmStopFail{}

	_, err := rs.Stop(context.Background(), &pb.StopRequest{})
	assert.Error(t, err)
}

type MockAlgorithmStopFail struct{}

func (m *MockAlgorithmStopFail) Run() error  { return nil }
func (m *MockAlgorithmStopFail) Stop() error { return fmt.Errorf("stop failed") }
