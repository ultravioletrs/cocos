// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package qemu

import (
	"log/slog"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ultravioletrs/cocos/manager/vm/mocks"
	pkgmanager "github.com/ultravioletrs/cocos/pkg/manager"
)

const testComputationID = "test-computation"

func TestNewVM(t *testing.T) {
	config := VMInfo{Config: Config{}}

	vm := NewVM(config, testComputationID, slog.Default())

	assert.NotNil(t, vm)
	assert.IsType(t, &qemuVM{}, vm)
}

func TestStart(t *testing.T) {
	// Create a temporary file for testing
	tmpFile, err := os.CreateTemp("", "test-ovmf-vars")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	config := VMInfo{Config: Config{
		OVMFVarsConfig: OVMFVarsConfig{
			File: tmpFile.Name(),
		},
		QemuBinPath: "echo",
	}}

	vm := NewVM(config, testComputationID, slog.Default()).(*qemuVM)

	err = vm.Start()
	assert.NoError(t, err)
	assert.NotNil(t, vm.cmd)

	_ = vm.Stop()
}

func TestStartSudo(t *testing.T) {
	// Create a temporary file for testing
	tmpFile, err := os.CreateTemp("", "test-ovmf-vars")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	config := VMInfo{Config: Config{
		OVMFVarsConfig: OVMFVarsConfig{
			File: tmpFile.Name(),
		},
		QemuBinPath: "echo",
		UseSudo:     true,
	}}

	vm := NewVM(config, testComputationID, slog.Default()).(*qemuVM)

	err = vm.Start()
	assert.NoError(t, err)
	assert.NotNil(t, vm.cmd)

	_ = vm.Stop()
}

func TestStop(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		cmd := exec.Command("echo", "test")
		err := cmd.Start()
		assert.NoError(t, err)
		sm := new(mocks.StateMachine)
		sm.On("Transition", pkgmanager.StopComputationRun).Return(nil)

		vm := &qemuVM{
			cmd: &exec.Cmd{
				Process: cmd.Process,
			},
			StateMachine: sm,
		}

		err = vm.Stop()
		assert.NoError(t, err)
	})
	t.Run("transition error", func(t *testing.T) {
		cmd := exec.Command("echo", "test")
		err := cmd.Start()
		assert.NoError(t, err)
		sm := new(mocks.StateMachine)
		sm.On("Transition", pkgmanager.StopComputationRun).Return(assert.AnError)
		sm.On("State").Return(pkgmanager.Stopped.String())

		vm := &qemuVM{
			cmd: &exec.Cmd{
				Process: cmd.Process,
			},
			StateMachine: sm,
		}

		err = vm.Stop()
		assert.NoError(t, err)
	})
}

func TestSetProcess(t *testing.T) {
	vm := &qemuVM{
		vmi: VMInfo{
			Config: Config{QemuBinPath: "echo"}, // Use 'echo' as a dummy QEMU binary
		},
	}

	err := vm.SetProcess(os.Getpid()) // Use current process as a dummy
	assert.NoError(t, err)
	assert.NotNil(t, vm.cmd)
	assert.NotNil(t, vm.cmd.Process)
}

func TestGetProcess(t *testing.T) {
	expectedPid := 12345
	vm := &qemuVM{
		cmd: &exec.Cmd{
			Process: &os.Process{Pid: expectedPid},
		},
	}

	pid := vm.GetProcess()
	assert.Equal(t, expectedPid, pid)
}

func TestGetCID(t *testing.T) {
	expectedCID := 42
	vm := &qemuVM{
		vmi: VMInfo{
			Config: Config{
				VSockConfig: VSockConfig{
					GuestCID: expectedCID,
				},
			},
		},
	}

	cid := vm.GetCID()
	assert.Equal(t, expectedCID, cid)
}

func TestGetConfig(t *testing.T) {
	expectedConfig := VMInfo{
		Config: Config{
			QemuBinPath: "echo",
		},
	}
	vm := &qemuVM{
		vmi: expectedConfig,
	}

	config := vm.GetConfig()
	assert.Equal(t, expectedConfig, config)
}
