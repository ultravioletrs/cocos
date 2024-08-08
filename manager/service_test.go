// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/ultravioletrs/cocos/manager/qemu"
	"github.com/ultravioletrs/cocos/manager/vm"
	"github.com/ultravioletrs/cocos/manager/vm/mocks"
	"github.com/ultravioletrs/cocos/pkg/manager"
)

func TestNew(t *testing.T) {
	cfg := qemu.Config{}
	logger := slog.Default()
	eventsChan := make(chan *manager.ClientStreamMessage)
	vmf := new(mocks.Provider)

	service, err := New(cfg, "", logger, eventsChan, vmf.Execute)
	assert.NoError(t, err)

	assert.NotNil(t, service)
	assert.IsType(t, &managerService{}, service)
}

func TestRun(t *testing.T) {
	vmf := new(mocks.Provider)
	vmMock := new(mocks.VM)
	vmf.On("Execute", mock.Anything, mock.Anything, mock.Anything).Return(vmMock)
	tests := []struct {
		name          string
		req           *manager.ComputationRunReq
		vmStartError  error
		expectedError error
	}{
		{
			name: "Successful run",
			req: &manager.ComputationRunReq{
				Id:   "test-computation",
				Name: "Test Computation",
				Algorithm: &manager.Algorithm{
					Hash: make([]byte, hashLength),
				},
				AgentConfig: &manager.AgentConfig{},
			},
			vmStartError:  nil,
			expectedError: nil,
		},
		{
			name: "VM start failure",
			req: &manager.ComputationRunReq{
				Id:   "test-computation",
				Name: "Test Computation",
				Algorithm: &manager.Algorithm{
					Hash: make([]byte, hashLength),
				},
				AgentConfig: &manager.AgentConfig{},
			},
			vmStartError:  assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.vmStartError == nil {
				vmMock.On("Start").Return(nil).Once()
			} else {
				vmMock.On("Start").Return(tt.vmStartError).Once()
			}

			vmMock.On("SendAgentConfig", mock.Anything).Return(nil)

			qemuCfg := qemu.Config{
				VSockConfig: qemu.VSockConfig{
					GuestCID: 3,
					Vnc:      5900,
				},
			}
			logger := slog.Default()
			eventsChan := make(chan *manager.ClientStreamMessage, 10)

			ms := &managerService{
				qemuCfg:    qemuCfg,
				logger:     logger,
				agents:     make(map[int]string),
				vms:        make(map[string]vm.VM),
				eventsChan: eventsChan,
				vmFactory:  vmf.Execute,
			}

			ctx := context.Background()

			port, err := ms.Run(ctx, tt.req)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedError)
				assert.Empty(t, port)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, port)
				assert.Len(t, ms.vms, 1)
				assert.Len(t, ms.agents, 1)
			}

			vmf.AssertExpectations(t)

			// Clear the events channel
			for len(eventsChan) > 0 {
				<-eventsChan
			}
		})
	}
}

func TestStop(t *testing.T) {
	tests := []struct {
		name           string
		computationID  string
		vmStopError    error
		expectedError  error
		initialVMCount int
	}{
		{
			name:           "Successful stop",
			computationID:  "existing-computation",
			vmStopError:    nil,
			expectedError:  nil,
			initialVMCount: 1,
		},
		{
			name:           "Non-existent computation",
			computationID:  "non-existent-computation",
			vmStopError:    nil,
			expectedError:  ErrNotFound,
			initialVMCount: 0,
		},
		{
			name:           "VM stop error",
			computationID:  "error-computation",
			vmStopError:    assert.AnError,
			expectedError:  assert.AnError,
			initialVMCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := &managerService{
				vms: make(map[string]vm.VM),
			}
			vmMock := new(mocks.VM)

			if tt.vmStopError == nil {
				vmMock.On("Stop").Return(nil).Once()
			} else {
				vmMock.On("Stop").Return(assert.AnError).Once()
			}

			if tt.initialVMCount > 0 {
				ms.vms[tt.computationID] = vmMock
			}

			err := ms.Stop(context.Background(), tt.computationID)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Len(t, ms.vms, 0)
			}
		})
	}
}

func TestGetFreePort(t *testing.T) {
	port, err := getFreePort(6000, 6100)

	assert.NoError(t, err)
	assert.Greater(t, port, 0)
}

func TestPublishEvent(t *testing.T) {
	tests := []struct {
		name          string
		event         string
		computationID string
		status        string
		details       json.RawMessage
	}{
		{
			name:          "Standard event",
			event:         "test-event",
			computationID: "test-computation",
			status:        "test-status",
			details:       nil,
		},
		{
			name:          "Event with details",
			event:         "detailed-event",
			computationID: "detailed-computation",
			status:        "detailed-status",
			details:       json.RawMessage(`{"key": "value"}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventsChan := make(chan *manager.ClientStreamMessage, 1)
			ms := &managerService{
				eventsChan: eventsChan,
			}

			ms.publishEvent(tt.event, tt.computationID, tt.status, tt.details)

			assert.Len(t, eventsChan, 1)
			event := <-eventsChan
			assert.Equal(t, tt.event, event.GetAgentEvent().EventType)
			assert.Equal(t, tt.computationID, event.GetAgentEvent().ComputationId)
			assert.Equal(t, tt.status, event.GetAgentEvent().Status)
			assert.Equal(t, "manager", event.GetAgentEvent().Originator)
			assert.Equal(t, tt.details, json.RawMessage(event.GetAgentEvent().Details))
		})
	}
}
