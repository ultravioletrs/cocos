// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package algorithm

import (
	"strings"
	"testing"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/ultravioletrs/cocos/agent/events/mocks"
)

func TestStdoutWrite(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Single line",
			input:    "Hello, World!",
			expected: []string{"Hello, World!"},
		},
		{
			name:     "Multiple lines",
			input:    "Line 1\nLine 2\nLine 3",
			expected: []string{"Line 1\nLine 2\nLine 3"},
		},
		{
			name:     "Long input",
			input:    strings.Repeat("a", bufSize+100),
			expected: []string{strings.Repeat("a", bufSize), strings.Repeat("a", 100)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout := &Stdout{Logger: mglog.NewMock()}
			n, err := stdout.Write([]byte(tt.input))

			assert.NoError(t, err)
			assert.Equal(t, len(tt.input), n)
		})
	}
}

func TestStderrWrite(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Single line",
			input:    "Error: Something went wrong",
			expected: []string{"Error: Something went wrong"},
		},
		{
			name:     "Multiple lines",
			input:    "Error 1\nError 2\nError 3",
			expected: []string{"Error 1\nError 2\nError 3"},
		},
		{
			name:     "Long input",
			input:    strings.Repeat("e", bufSize+100),
			expected: []string{strings.Repeat("e", bufSize), strings.Repeat("e", 100)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockEventService := mocks.NewService(t)
			mockEventService.On("SendEvent", "algorithm-run", "failed", mock.Anything).Return(nil)

			stderr := &Stderr{Logger: mglog.NewMock(), EventSvc: mockEventService}
			n, err := stderr.Write([]byte(tt.input))

			assert.NoError(t, err)
			assert.Equal(t, len(tt.input), n)
			mockEventService.AssertExpectations(t)
		})
	}
}
