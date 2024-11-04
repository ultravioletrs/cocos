// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/agent/events/mocks"
	qpmocks "github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider/mocks"
)

func TestSetDefaultValues(t *testing.T) {
	tests := []struct {
		name     string
		input    agent.Computation
		expected agent.Computation
	}{
		{
			name: "Empty config",
			input: agent.Computation{
				AgentConfig: agent.AgentConfig{},
			},
			expected: agent.Computation{
				AgentConfig: agent.AgentConfig{
					LogLevel: "info",
					Port:     "7002",
				},
			},
		},
		{
			name: "Partial config",
			input: agent.Computation{
				AgentConfig: agent.AgentConfig{
					LogLevel: "debug",
				},
			},
			expected: agent.Computation{
				AgentConfig: agent.AgentConfig{
					LogLevel: "debug",
					Port:     "7002",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setDefaultValues(&tt.input)
			assert.Equal(t, tt.expected, tt.input)
		})
	}
}

func TestNewService(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	eventSvc := new(mocks.Service)
	eventSvc.On("SendEvent", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	cmp := agent.Computation{
		ID: "test-computation",
		AgentConfig: agent.AgentConfig{
			LogLevel: "info",
			Port:     "7002",
		},
	}
	qp := new(qpmocks.QuoteProvider)

	svc := newService(ctx, logger, eventSvc, cmp, qp)

	assert.NotNil(t, svc)
}

func TestVerifyManifest(t *testing.T) {
	cfg := agent.Computation{
		ID: "test-computation",
		AgentConfig: agent.AgentConfig{
			LogLevel: "info",
			Port:     "7002",
		},
	}

	mockQP := new(qpmocks.QuoteProvider)
	mockQP.On("GetRawQuote", mock.Anything).Return([]byte{}, nil)

	err := verifyManifest(cfg, mockQP)

	assert.NoError(t, err)
}
