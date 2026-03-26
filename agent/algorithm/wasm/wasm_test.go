// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package wasm

import (
	"log/slog"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/ultravioletrs/cocos/agent/algorithm/logging"
	"github.com/ultravioletrs/cocos/agent/events/mocks"
)

func TestNewAlgorithm(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventsSvc := new(mocks.Service)
	algoFile := "test.wasm"
	args := []string{"arg1", "arg2"}

	algo := NewAlgorithm(logger, eventsSvc, args, algoFile, "")

	w, ok := algo.(*wasm)
	if !ok {
		t.Fatalf("NewAlgorithm did not return a *wasm")
	}

	if w.algoFile != algoFile {
		t.Errorf("Expected algoFile to be %s, got %s", algoFile, w.algoFile)
	}

	if len(w.args) != len(args) {
		t.Errorf("Expected %d args, got %d", len(args), len(w.args))
	}

	_, ok = w.stderr.(*logging.Stderr)
	if !ok {
		t.Errorf("Expected stderr to be *algorithm.Stderr")
	}

	_, ok = w.stdout.(*logging.Stdout)
	if !ok {
		t.Errorf("Expected stdout to be *algorithm.Stdout")
	}
}

func TestRunError(t *testing.T) {
	// Mock exec.Command to return an error
	execCommand = mockExecCommandError
	defer func() { execCommand = exec.Command }()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventsSvc := new(mocks.Service)
	eventsSvc.On("SendEvent", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return().Maybe()
	algoFile := "test.wasm"
	args := []string{"arg1", "arg2"}

	w := NewAlgorithm(logger, eventsSvc, args, algoFile, "").(*wasm)

	err := w.Run()
	if err == nil {
		t.Errorf("Run() should have returned an error")
	}
}

func mockExecCommand(command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestHelperProcess", "--", command}
	cs = append(cs, args...)
	cmd := exec.Command(os.Args[0], cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
	return cmd
}

func mockExecCommandError(command string, args ...string) *exec.Cmd {
	cmd := mockExecCommand(command, args...)
	cmd.Env = append(cmd.Env, "GO_WANT_HELPER_PROCESS_ERROR=1")
	return cmd
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	if os.Getenv("GO_WANT_HELPER_PROCESS_SLEEP") == "1" {
		time.Sleep(10 * time.Second)
	}
	if os.Getenv("GO_WANT_HELPER_PROCESS_ERROR") == "1" {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestStop(t *testing.T) {
	t.Run("stop nil cmd", func(t *testing.T) {
		w := &wasm{}
		err := w.Stop()
		if err != nil {
			t.Errorf("Expected nil error, got %v", err)
		}
	})

	t.Run("stop with running process", func(t *testing.T) {
		oldExecCommand := execCommand
		execCommand = mockExecCommand
		defer func() { execCommand = oldExecCommand }()

		w := &wasm{
			algoFile: "test.wasm",
			stdout:   os.Stdout,
			stderr:   os.Stderr,
		}

		// We need to simulate a running process.
		// mockExecCommand returns a command that runs TestHelperProcess.
		// If we don't call Wait(), it keeps running? No, TestHelperProcess exits immediately.
		// Let's modify TestHelperProcess to sleep if an env var is set.

		w.cmd = mockExecCommand("sleep", "10")
		w.cmd.Env = append(w.cmd.Env, "GO_WANT_HELPER_PROCESS_SLEEP=1")
		if err := w.cmd.Start(); err != nil {
			t.Fatalf("Failed to start command: %v", err)
		}

		err := w.Stop()
		if err != nil {
			t.Errorf("Expected nil error, got %v", err)
		}
		_ = w.cmd.Wait()
	})
}

// Update TestHelperProcess to handle sleep.
func TestHelperProcessSleep(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	if os.Getenv("GO_WANT_HELPER_PROCESS_SLEEP") == "1" {
		time.Sleep(10 * time.Second)
	}
	if os.Getenv("GO_WANT_HELPER_PROCESS_ERROR") == "1" {
		os.Exit(1)
	}
	os.Exit(0)
}
