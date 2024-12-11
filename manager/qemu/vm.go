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
	firmwareVars    = "OVMF_VARS"
	KernelFile      = "bzImage"
	rootfsFile      = "rootfs.cpio"
	tmpDir          = "/tmp"
	interval        = 5 * time.Second
	shutdownTimeout = 30 * time.Second
)

type VMInfo struct {
	Config    Config
	LaunchTCB uint64 `env:"LAUNCH_TCB" envDefault:"0"`
}

type qemuVM struct {
	vmi              VMInfo
	cmd              *exec.Cmd
	eventsLogsSender vm.EventSender
	computationId    string
	vm.StateMachine
}

func NewVM(config interface{}, eventsLogsSender vm.EventSender, computationId string) vm.VM {
	return &qemuVM{
		vmi:              config.(VMInfo),
		eventsLogsSender: eventsLogsSender,
		computationId:    computationId,
		StateMachine:     vm.NewStateMachine(),
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
		return err
	}

	v.vmi.Config.NetDevConfig.ID = fmt.Sprintf("%s-%s", v.vmi.Config.NetDevConfig.ID, id)
	v.vmi.Config.SevConfig.ID = fmt.Sprintf("%s-%s", v.vmi.Config.SevConfig.ID, id)

	if !v.vmi.Config.KernelHash {
		// Copy firmware vars file.
		srcFile := v.vmi.Config.OVMFVarsConfig.File
		dstFile := fmt.Sprintf("%s/%s-%s.fd", tmpDir, firmwareVars, id)
		err = internal.CopyFile(srcFile, dstFile)
		if err != nil {
			return err
		}
		v.vmi.Config.OVMFVarsConfig.File = dstFile
	}

	exe, args, err := v.executableAndArgs()
	if err != nil {
		return err
	}

	v.cmd = exec.Command(exe, args...)
	v.cmd.Stdout = &vm.Stdout{ComputationId: v.computationId, EventSender: v.eventsLogsSender}
	v.cmd.Stderr = &vm.Stderr{EventSender: v.eventsLogsSender, ComputationId: v.computationId, StateMachine: v.StateMachine}

	return v.cmd.Start()
}

func (v *qemuVM) Stop() error {
	defer func() {
		err := v.StateMachine.Transition(manager.StopComputationRun)
		if err != nil {
			if err := v.eventsLogsSender(&vm.Event{
				EventType:     v.StateMachine.State(),
				Timestamp:     timestamppb.Now(),
				ComputationId: v.computationId,
				Originator:    "manager",
				Status:        manager.Warning.String(),
			}); err != nil {
				return
			}
		}
	}()
	err := v.cmd.Process.Signal(syscall.SIGTERM)
	if err != nil {
		return fmt.Errorf("failed to send SIGTERM: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := v.cmd.Process.Wait()
		done <- err
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(shutdownTimeout):
		err := v.cmd.Process.Kill()
		if err != nil {
			return fmt.Errorf("failed to kill process: %v", err)
		}
	}

	return nil
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
	exe, err := exec.LookPath(v.vmi.Config.QemuBinPath)
	if err != nil {
		return "", nil, err
	}

	args := v.vmi.Config.ConstructQemuArgs()

	if v.vmi.Config.UseSudo {
		args = append([]string{exe}, args...)
		exe = "sudo"
	}

	return exe, args, nil
}

func (v *qemuVM) checkVMProcessPeriodically() {
	for {
		if !processExists(v.GetProcess()) {
			if err := v.eventsLogsSender(&vm.Event{
				EventType:     v.StateMachine.State(),
				Timestamp:     timestamppb.Now(),
				ComputationId: v.computationId,
				Originator:    "manager",
				Status:        manager.Stopped.String(),
			}); err != nil {
				return
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
	// To test whether the process actually exists, see whether p.Signal(syscall.Signal(0)) reports an error.
	if err = process.Signal(syscall.Signal(0)); err == nil {
		return true
	}
	if err == syscall.ESRCH {
		return false
	}
	return false
}

func (v *qemuVM) GetCID() int {
	return v.vmi.Config.GuestCID
}

func (v *qemuVM) GetConfig() interface{} {
	return v.vmi
}
