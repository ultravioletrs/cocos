// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package python

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultravioletrs/cocos/agent/algorithm/logging"
	"github.com/ultravioletrs/cocos/agent/events/mocks"
	"google.golang.org/grpc/metadata"
)

const runtime = "python3"

func TestPythonRunTimeToContext(t *testing.T) {
	ctx := context.Background()
	newCtx := PythonRunTimeToContext(ctx, runtime)

	md, ok := metadata.FromOutgoingContext(newCtx)
	if !ok {
		t.Fatal("Expected metadata in context")
	}

	values := md.Get(PyRuntimeKey)
	if len(values) != 1 || values[0] != runtime {
		t.Errorf("Expected runtime %s, got %v", runtime, values)
	}
}

func TestPythonRunTimeFromContext(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(PyRuntimeKey, runtime))

	got := PythonRunTimeFromContext(ctx)
	if got != runtime {
		t.Errorf("Expected runtime %s, got %s", runtime, got)
	}
}

func TestNewAlgorithm(t *testing.T) {
	logger := &slog.Logger{}
	eventsSvc := new(mocks.Service)
	requirementsFile := "requirements.txt"
	algoFile := "algorithm.py"
	args := []string{"--arg1", "value1"}

	algo := NewAlgorithm(logger, eventsSvc, runtime, requirementsFile, algoFile, args)

	p, ok := algo.(*python)
	if !ok {
		t.Fatal("Expected *python type")
	}

	if p.runtime != runtime {
		t.Errorf("Expected runtime %s, got %s", runtime, p.runtime)
	}
	if p.requirementsFile != requirementsFile {
		t.Errorf("Expected requirementsFile %s, got %s", requirementsFile, p.requirementsFile)
	}
	if p.algoFile != algoFile {
		t.Errorf("Expected algoFile %s, got %s", algoFile, p.algoFile)
	}
	if len(p.args) != len(args) {
		t.Errorf("Expected %d args, got %d", len(args), len(p.args))
	}
}

func TestRun(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "python-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	scriptContent := []byte("print('Hello, World!')")
	scriptPath := filepath.Join(tmpDir, "test_script.py")
	if err := os.WriteFile(scriptPath, scriptContent, 0o644); err != nil {
		t.Fatal(err)
	}

	eventsSvc := new(mocks.Service)

	var stdout, stderr bytes.Buffer

	algo := &python{
		algoFile: scriptPath,
		stderr:   io.MultiWriter(&stderr, &logging.Stderr{Logger: slog.Default(), EventSvc: eventsSvc}),
		stdout:   io.MultiWriter(&stdout, &logging.Stdout{Logger: slog.Default()}),
		runtime:  "python3",
	}

	err = algo.Run()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	expectedOutput := "Hello, World!\n"
	if !strings.Contains(stdout.String(), expectedOutput) {
		t.Errorf("Expected output to contain %q, got %q", expectedOutput, stdout.String())
	}
}

func TestRunWithRequirements(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "python-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	scriptContent := []byte("import requests\nprint(requests.__version__)")
	scriptPath := filepath.Join(tmpDir, "test_script.py")
	if err := os.WriteFile(scriptPath, scriptContent, 0o644); err != nil {
		t.Fatal(err)
	}

	requirementsContent := []byte("requests==2.26.0")
	requirementsPath := filepath.Join(tmpDir, "requirements.txt")
	if err := os.WriteFile(requirementsPath, requirementsContent, 0o644); err != nil {
		t.Fatal(err)
	}

	eventsSvc := new(mocks.Service)

	var stdout, stderr bytes.Buffer

	algo := &python{
		algoFile:         scriptPath,
		requirementsFile: requirementsPath,
		stderr:           io.MultiWriter(&stderr, &logging.Stderr{Logger: slog.Default(), EventSvc: eventsSvc}),
		stdout:           io.MultiWriter(&stdout, &logging.Stdout{Logger: slog.Default()}),
		runtime:          "python3",
	}

	err = algo.Run()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !strings.Contains(stdout.String(), "2.26.0") {
		t.Errorf("Expected output to contain requests version 2.26.0, got %q", stdout.String())
	}
}
