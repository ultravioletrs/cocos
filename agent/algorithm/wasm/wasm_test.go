// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package wasm

import (
	"log/slog"
	"os"
	"os/exec"
	"testing"

	"github.com/ultravioletrs/cocos/agent/algorithm/logging"
	"github.com/ultravioletrs/cocos/agent/events/mocks"
)

func TestNewAlgorithm(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventsSvc := new(mocks.Service)
	algoFile := "test.wasm"
	args := []string{"arg1", "arg2"}

	algo := NewAlgorithm(logger, eventsSvc, algoFile, args)

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
	algoFile := "test.wasm"
	args := []string{"arg1", "arg2"}

	w := NewAlgorithm(logger, eventsSvc, algoFile, args).(*wasm)

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
	if os.Getenv("GO_WANT_HELPER_PROCESS_ERROR") == "1" {
		os.Exit(1)
	}
	os.Exit(0)
}

var execCommand = exec.Command
