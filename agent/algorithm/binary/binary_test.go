// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package binary

import (
	"bytes"
	"log/slog"
	"os"
	"testing"

	"github.com/ultravioletrs/cocos/agent/algorithm/logging"
	"github.com/ultravioletrs/cocos/agent/events/mocks"
)

func TestNewAlgorithm(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventsSvc := new(mocks.Service)
	algoFile := "/path/to/algo"
	args := []string{"arg1", "arg2"}

	algo := NewAlgorithm(logger, eventsSvc, algoFile, args)

	b, ok := algo.(*binary)
	if !ok {
		t.Fatalf("NewAlgorithm did not return a *binary")
	}

	if b.algoFile != algoFile {
		t.Errorf("Expected algoFile to be %s, got %s", algoFile, b.algoFile)
	}

	if len(b.args) != len(args) {
		t.Errorf("Expected %d args, got %d", len(args), len(b.args))
	}

	for i, arg := range args {
		if b.args[i] != arg {
			t.Errorf("Expected arg %d to be %s, got %s", i, arg, b.args[i])
		}
	}

	if _, ok := b.stderr.(*logging.Stderr); !ok {
		t.Errorf("Expected stderr to be *algorithm.Stderr")
	}

	if _, ok := b.stdout.(*logging.Stdout); !ok {
		t.Errorf("Expected stdout to be *algorithm.Stdout")
	}
}

func TestBinaryRun(t *testing.T) {
	tests := []struct {
		name          string
		algoFile      string
		args          []string
		expectedError bool
	}{
		{
			name:          "Successful execution",
			algoFile:      "echo",
			args:          []string{"Hello, World!"},
			expectedError: false,
		},
		{
			name:          "Non-existent binary",
			algoFile:      "non_existent_binary",
			args:          []string{},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
			eventsSvc := new(mocks.Service)

			b := NewAlgorithm(logger, eventsSvc, tt.algoFile, tt.args).(*binary)

			var stdout, stderr bytes.Buffer
			b.stdout = &stdout
			b.stderr = &stderr

			err := b.Run()

			if tt.expectedError && err == nil {
				t.Errorf("Expected an error, but got none")
			}

			if !tt.expectedError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if !tt.expectedError {
				if stdout.Len() == 0 {
					t.Errorf("Expected non-empty stdout")
				}
			}
		})
	}
}
