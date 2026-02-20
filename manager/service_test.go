// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"testing"

	mglog "github.com/absmach/supermq/logger"
	"github.com/absmach/supermq/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/manager/qemu"
	persistenceMocks "github.com/ultravioletrs/cocos/manager/qemu/mocks"
	"github.com/ultravioletrs/cocos/manager/vm"
	"github.com/ultravioletrs/cocos/manager/vm/mocks"
	"github.com/ultravioletrs/cocos/pkg/attestation/policy"
)

func TestNew(t *testing.T) {
	cfg := qemu.Config{
		HostFwdRange: "6000-6100",
	}
	logger := slog.Default()
	vmf := new(mocks.Provider)

	service, err := New(cfg, "", "", 0, nil, logger, vmf.Execute, "", 10)
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
		name          string
		vmStartError  error
		expectedError error
		ttl           string
	}{
		{
			name:          "Successful run",
			vmStartError:  nil,
			expectedError: nil,
			ttl:           "",
		},
		{
			name:          "VM start failure",
			vmStartError:  assert.AnError,
			expectedError: assert.AnError,
			ttl:           "",
		},
		{
			name:          "With TTL",
			vmStartError:  nil,
			expectedError: nil,
			ttl:           "10s",
		},
		{
			name:          "with exceeded max vms",
			vmStartError:  nil,
			expectedError: errors.New("maximum number of VMs exceeded"),
			ttl:           "",
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
				EnableTDX: true,
			}
			logger := slog.Default()

			ms := &managerService{
				qemuCfg: qemuCfg,
				tdxPolicyConfig: &policy.TDXConfig{
					SGXVendorID:  [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
					MinTdxSvn:    [16]byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
					MrSeam:       []byte{0x21, 0x22, 0x23, 0x24},
					TdAttributes: [8]byte{0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c},
					Xfam:         [8]byte{0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34},
					MrTd:         []byte{0x35, 0x36, 0x37, 0x38},
					RTMR: [4][]byte{
						{0x41, 0x42, 0x43, 0x44},
						{0x45, 0x46, 0x47, 0x48},
						{0x49, 0x4a, 0x4b, 0x4c},
						{0x4d, 0x4e, 0x4f, 0x50},
					},
				},
				logger:      logger,
				vms:         make(map[string]vm.VM),
				vmFactory:   vmf.Execute,
				persistence: persistence,
				ttlManager:  NewTTLManager(),
			}

			if tt.name == "with exceeded max vms" {
				ms.maxVMs = 1
				ms.vms["existing-vm"] = vmMock // Simulate an existing VM
			}

			ctx := context.Background()

			port, _, err := ms.CreateVM(ctx, &CreateReq{Ttl: tt.ttl})

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Empty(t, port)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, port)
				assert.Len(t, ms.vms, 1)
			}

			vmf.AssertExpectations(t)
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
			ms := &managerService{
				logger:      logger,
				vms:         make(map[string]vm.VM),
				persistence: persistence,
				ttlManager:  NewTTLManager(),
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

			err := ms.RemoveVM(context.Background(), tt.computationID)

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
	assert.GreaterOrEqual(t, port, 6000)

	_, err = net.Listen("tcp", net.JoinHostPort("localhost", fmt.Sprint(port)))
	assert.NoError(t, err)

	port, err = getFreePort(6000, 6100)
	assert.NoError(t, err)
	assert.Greater(t, port, 6000)
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

func TestShutdown(t *testing.T) {
	ms := &managerService{
		vms:        make(map[string]vm.VM),
		ttlManager: NewTTLManager(),
		logger:     mglog.NewMock(),
	}

	vmMock := new(mocks.VM)
	vmMock.On("Stop").Return(nil).Once()
	ms.vms["test-vm"] = vmMock

	err := ms.Shutdown()
	assert.NoError(t, err)

	assert.Len(t, ms.vms, 0)
}
