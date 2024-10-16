// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package qemu

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/ultravioletrs/cocos/manager/vm"
	"github.com/ultravioletrs/cocos/manager/vm/mocks"
	pkgmanager "github.com/ultravioletrs/cocos/pkg/manager"
)

const testComputationID = "test-computation"

func TestNewVM(t *testing.T) {
	config := Config{}

	vm := NewVM(config, func(event vm.EventsLogs) {}, testComputationID)

	assert.NotNil(t, vm)
	assert.IsType(t, &qemuVM{}, vm)
}

func TestStart(t *testing.T) {
	// Create a temporary file for testing
	tmpFile, err := os.CreateTemp("", "test-ovmf-vars")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	config := Config{
		OVMFVarsConfig: OVMFVarsConfig{
			File: tmpFile.Name(),
		},
		QemuBinPath: "echo",
	}

	vm := NewVM(config, func(event vm.EventsLogs) {}, testComputationID).(*qemuVM)

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

	config := Config{
		OVMFVarsConfig: OVMFVarsConfig{
			File: tmpFile.Name(),
		},
		QemuBinPath: "echo",
		UseSudo:     true,
	}

	vm := NewVM(config, func(event vm.EventsLogs) {}, testComputationID).(*qemuVM)

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
			eventsLogsSender: func(event vm.EventsLogs) {
			},
		}

		err = vm.Stop()
		assert.NoError(t, err)
	})
}

func TestSetProcess(t *testing.T) {
	vm := &qemuVM{
		config: Config{
			QemuBinPath: "echo", // Use 'echo' as a dummy QEMU binary
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
		config: Config{
			VSockConfig: VSockConfig{
				GuestCID: expectedCID,
			},
		},
	}

	cid := vm.GetCID()
	assert.Equal(t, expectedCID, cid)
}

func TestGetConfig(t *testing.T) {
	expectedConfig := Config{
		QemuBinPath: "echo",
	}
	vm := &qemuVM{
		config: expectedConfig,
	}

	config := vm.GetConfig()
	assert.Equal(t, expectedConfig, config)
}

func TestCheckVMProcessPeriodically(t *testing.T) {
	logsChan := make(chan vm.EventsLogs, 1)
	vmi := &qemuVM{
		eventsLogsSender: func(event vm.EventsLogs) {
			logsChan <- event
		},
		computationId: testComputationID,
		cmd: &exec.Cmd{
			Process: &os.Process{Pid: -1}, // Use an invalid PID to simulate a stopped process
		},
		StateMachine: vm.NewStateMachine(),
	}

	go vmi.checkVMProcessPeriodically()

	select {
	case msg := <-logsChan:
		assert.NotNil(t, msg)
		msgE := msg.(*vm.Event)
		assert.Equal(t, testComputationID, msgE.ComputationId)
		assert.Equal(t, pkgmanager.VmProvision.String(), msgE.EventType)
		assert.Equal(t, pkgmanager.Stopped.String(), msgE.Status)
	case <-time.After(2 * interval):
		t.Fatal("Timeout waiting for VM stopped message")
	}
}
