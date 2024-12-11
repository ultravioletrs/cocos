// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"testing"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/manager/qemu"
	persistenceMocks "github.com/ultravioletrs/cocos/manager/qemu/mocks"
	"github.com/ultravioletrs/cocos/manager/vm"
	"github.com/ultravioletrs/cocos/manager/vm/mocks"
)

func TestNew(t *testing.T) {
	cfg := qemu.Config{
		HostFwdRange: "6000-6100",
	}
	logger := slog.Default()
	eventsChan := make(chan *ClientStreamMessage)
	vmf := new(mocks.Provider)

	service, err := New(cfg, "", logger, eventsChan, vmf.Execute, "")
	require.NoError(t, err)

	assert.NotNil(t, service)
	assert.IsType(t, &managerService{}, service)
}

func TestRun(t *testing.T) {
	vmf := new(mocks.Provider)
	vmMock := new(mocks.VM)
	persistence := new(persistenceMocks.Persistence)
	vmf.On("Execute", mock.Anything, mock.Anything, mock.Anything).Return(vmMock)
	tests := []struct {
		name           string
		req            *ComputationRunReq
		binaryBehavior string
		vmStartError   error
		expectedError  error
	}{
		{
			name: "Successful run",
			req: &ComputationRunReq{
				Id:   "test-computation",
				Name: "Test Computation",
				Algorithm: &Algorithm{
					Hash: make([]byte, hashLength),
				},
				AgentConfig: &AgentConfig{},
			},
			binaryBehavior: "success",
			vmStartError:   nil,
			expectedError:  nil,
		},
		{
			name: "VM start failure",
			req: &ComputationRunReq{
				Id:   "test-computation",
				Name: "Test Computation",
				Algorithm: &Algorithm{
					Hash: make([]byte, hashLength),
				},
				AgentConfig: &AgentConfig{},
			},
			binaryBehavior: "success",
			vmStartError:   assert.AnError,
			expectedError:  assert.AnError,
		},
		{
			name: "Invalid algorithm hash",
			req: &ComputationRunReq{
				Id:   "test-computation",
				Name: "Test Computation",
				Algorithm: &Algorithm{
					Hash: make([]byte, hashLength-1),
				},
				AgentConfig: &AgentConfig{},
			},
			binaryBehavior: "success",
			vmStartError:   nil,
			expectedError:  errInvalidHashLength,
		},
		{
			name: "Invalid dataset hash",
			req: &ComputationRunReq{
				Id:   "test-computation",
				Name: "Test Computation",
				Algorithm: &Algorithm{
					Hash: make([]byte, hashLength),
				},
				AgentConfig: &AgentConfig{},
				Datasets: []*Dataset{
					{
						Hash: make([]byte, hashLength-1),
					},
				},
			},
			binaryBehavior: "success",
			vmStartError:   nil,
			expectedError:  errInvalidHashLength,
		},
		{
			name: "Invalid attestation policy",
			req: &ComputationRunReq{
				Id:   "test-computation",
				Name: "Test Computation",
				Algorithm: &Algorithm{
					Hash: make([]byte, hashLength),
				},
				AgentConfig: &AgentConfig{},
			},
			binaryBehavior: "fail",
			vmStartError:   nil,
			expectedError:  ErrFailedToCreateAttestationPolicy,
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
			vmMock.On("GetProcess").Return(1234)
			vmMock.On("Transition", mock.Anything).Return(nil)

			persistence.On("SaveVM", mock.Anything).Return(nil)

			qemuCfg := qemu.Config{
				VSockConfig: qemu.VSockConfig{
					GuestCID: 3,
				},
			}
			logger := slog.Default()
			eventsChan := make(chan *ClientStreamMessage, 10)

			tempDir := CreateDummyAttestationPolicyBinary(t, tt.binaryBehavior)
			defer os.RemoveAll(tempDir)

			ms := &managerService{
				qemuCfg:                     qemuCfg,
				attestationPolicyBinaryPath: tempDir,
				logger:                      logger,
				vms:                         make(map[string]vm.VM),
				eventsChan:                  eventsChan,
				vmFactory:                   vmf.Execute,
				persistence:                 persistence,
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
			}

			vmf.AssertExpectations(t)

			for len(eventsChan) > 0 {
				<-eventsChan
			}
		})
	}
}

func TestStop(t *testing.T) {
	vmf := new(mocks.Provider)
	vmMock := new(mocks.VM)
	persistence := new(persistenceMocks.Persistence)
	vmf.On("Execute", mock.Anything, mock.Anything, mock.Anything).Return(vmMock)

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
			logger := slog.Default()
			eventsChan := make(chan *ClientStreamMessage, 10)
			ms := &managerService{
				logger:      logger,
				vms:         make(map[string]vm.VM),
				eventsChan:  eventsChan,
				persistence: persistence,
			}
			vmMock := new(mocks.VM)

			if tt.vmStopError == nil {
				vmMock.On("Stop").Return(nil).Once()
			} else {
				vmMock.On("Stop").Return(assert.AnError).Once()
			}

			persistence.On("DeleteVM", tt.computationID).Return(nil)

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

			for len(eventsChan) > 0 {
				<-eventsChan
			}
		})
	}
}

func TestGetFreePort(t *testing.T) {
	port, err := getFreePort(6000, 6100)

	assert.NoError(t, err)
	assert.GreaterOrEqual(t, port, 6000)

	_, err = net.Listen("tcp", net.JoinHostPort("localhost", fmt.Sprint(port)))
	assert.NoError(t, err)

	port, err = getFreePort(6000, 6100)
	assert.NoError(t, err)
	assert.Greater(t, port, 6000)
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
			eventsChan := make(chan *ClientStreamMessage, 1)
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

func TestComputationHash(t *testing.T) {
	tests := []struct {
		name        string
		computation agent.Computation
		wantErr     bool
	}{
		{
			name: "Valid computation",
			computation: agent.Computation{
				ID:   "test-id",
				Name: "test-name",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := computationHash(tt.computation)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, hash)

				hash2, _ := computationHash(tt.computation)
				assert.Equal(t, hash, hash2)
			}
		})
	}
}

func TestDecodeRange(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantStart int
		wantEnd   int
		wantErr   bool
	}{
		{"Valid range", "1-5", 1, 5, false},
		{"Invalid format", "1:5", 0, 0, true},
		{"Start greater than end", "5-1", 0, 0, true},
		{"Non-numeric input", "a-b", 0, 0, true},
		{"Single number", "5", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end, err := decodeRange(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantStart, start)
				assert.Equal(t, tt.wantEnd, end)
			}
		})
	}
}

func TestRestoreVMs(t *testing.T) {
	mockPersistence := new(persistenceMocks.Persistence)
	vmf := new(mocks.Provider)
	vmMock := new(mocks.VM)
	vmf.On("Execute", mock.Anything, mock.Anything, mock.Anything).Return(vmMock)
	vmMock.On("SetProcess", mock.Anything).Return(nil)
	vmMock.On("Transition", mock.Anything).Return(nil)
	ms := &managerService{
		persistence: mockPersistence,
		vms:         make(map[string]vm.VM),
		eventsChan:  make(chan *ClientStreamMessage, 10),
		vmFactory:   vmf.Execute,
		logger:      mglog.NewMock(),
	}

	cmd := exec.Command("echo", "test")
	err := cmd.Start()
	assert.NoError(t, err)

	cmd2 := exec.Command("echo", "test")
	err = cmd2.Run()
	assert.NoError(t, err)

	mockPersistence.On("LoadVMs").Return([]qemu.VMState{
		{ID: "vm1", PID: cmd.Process.Pid},
		{ID: "vm2", PID: cmd2.Process.Pid},
		{ID: "vm3", PID: cmd2.Process.Pid},
	}, nil)

	mockPersistence.On("DeleteVM", "vm2").Return(nil)
	mockPersistence.On("DeleteVM", "vm3").Return(errors.New("failed to delete"))

	err = ms.restoreVMs()
	assert.NoError(t, err)

	assert.Len(t, ms.vms, 1)
	assert.Contains(t, ms.vms, "vm1")

	mockPersistence.AssertExpectations(t)
}

func TestProcessExists(t *testing.T) {
	ms := &managerService{}

	assert.True(t, ms.processExists(os.Getpid()))

	assert.False(t, ms.processExists(99999))

	if os.Getuid() != 0 { // Skip this test if running as root.
		assert.False(t, ms.processExists(1)) // PID 1 is usually the init process.
	}
}
