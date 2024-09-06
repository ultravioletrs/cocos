// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package qemu

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/gofrs/uuid"
	"github.com/ultravioletrs/cocos/internal"
	"github.com/ultravioletrs/cocos/manager/vm"
	"github.com/ultravioletrs/cocos/pkg/manager"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	firmwareVars = "OVMF_VARS"
	KernelFile   = "bzImage"
	rootfsFile   = "rootfs.cpio"
	tmpDir       = "/tmp"
	interval     = 5 * time.Second
)

type qemuVM struct {
	config        Config
	cmd           *exec.Cmd
	logsChan      chan *manager.ClientStreamMessage
	computationId string
}

func NewVM(config interface{}, logsChan chan *manager.ClientStreamMessage, computationId string) vm.VM {
	return &qemuVM{
		config:        config.(Config),
		logsChan:      logsChan,
		computationId: computationId,
	}
}

func (v *qemuVM) Start() (err error) {
	defer func() {
		if err == nil {
			go v.checkVMProcessPeriodically()
		}
	}()
	// Create unique qemu device identifiers
	id, err := uuid.NewV4()
	if err != nil {
		return
	}

	v.config.NetDevConfig.ID = fmt.Sprintf("%s-%s", v.config.NetDevConfig.ID, id)
	v.config.SevConfig.ID = fmt.Sprintf("%s-%s", v.config.SevConfig.ID, id)

	if !v.config.KernelHash {
		// Copy firmware vars file.
		srcFile := v.config.OVMFVarsConfig.File
		dstFile := fmt.Sprintf("%s/%s-%s.fd", tmpDir, firmwareVars, id)
		err = internal.CopyFile(srcFile, dstFile)
		if err != nil {
			return err
		}
		v.config.OVMFVarsConfig.File = dstFile
	}

	exe, args, err := v.executableAndArgs()
	if err != nil {
		return
	}

	v.cmd = exec.Command(exe, args...)
	v.cmd.Stdout = &vm.Stdout{LogsChan: v.logsChan, ComputationId: v.computationId}
	v.cmd.Stderr = &vm.Stderr{LogsChan: v.logsChan, ComputationId: v.computationId}

	return v.cmd.Start()
}

func (v *qemuVM) Stop() error {
	return v.cmd.Process.Kill()
}

func (v *qemuVM) SetProcess(pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}

	exe, args, err := v.executableAndArgs()
	if err != nil {
		return err
	}

	v.cmd = exec.Command(exe, args...)
	v.cmd.Process = process
	return nil
}

func (v *qemuVM) GetProcess() int {
	return v.cmd.Process.Pid
}

func (v *qemuVM) executableAndArgs() (string, []string, error) {
	exe, err := exec.LookPath(v.config.QemuBinPath)
	if err != nil {
		return "", nil, err
	}

	args := v.config.ConstructQemuArgs()

	if v.config.UseSudo {
		args = append([]string{exe}, args...)
		exe = "sudo"
	}

	return exe, args, nil
}

func (v *qemuVM) checkVMProcessPeriodically() {
	for {
		if !processExists(v.GetProcess()) {
			v.logsChan <- &manager.ClientStreamMessage{
				Message: &manager.ClientStreamMessage_AgentEvent{
					AgentEvent: &manager.AgentEvent{
						ComputationId: v.computationId,
						EventType:     "vm-running",
						Status:        "stopped",
						Timestamp:     timestamppb.Now(),
						Originator:    "manager",
					},
				},
			}
			break
		}
		time.Sleep(interval)
	}
}

func processExists(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// On Unix systems, FindProcess always succeeds and returns a Process for the given pid, regardless of whether the process exists.
	//To test whether the process actually exists, see whether p.Signal(syscall.Signal(0)) reports an error.
	if err = process.Signal(syscall.Signal(0)); err == nil {
		return true
	}
	if err == syscall.ESRCH {
		return false
	}
	return false
}

func (v *qemuVM) GetCID() int {
	return v.config.GuestCID
}
