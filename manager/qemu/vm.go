// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package qemu

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/gofrs/uuid"
	"github.com/ultravioletrs/cocos/internal"
	"github.com/ultravioletrs/cocos/manager/vm"
	"github.com/ultravioletrs/cocos/pkg/manager"
)

const (
	firmwareVars    = "OVMF_VARS"
	KernelFile      = "bzImage"
	rootfsFile      = "rootfs.cpio"
	tmpDir          = "/tmp"
	diskDstName     = "cvmDisk"
	interval        = 5 * time.Second
	shutdownTimeout = 30 * time.Second
)

type VMInfo struct {
	Config    Config
	LaunchTCB uint64 `env:"LAUNCH_TCB" envDefault:"0"`
}

type qemuVM struct {
	vmi    VMInfo
	cmd    *exec.Cmd
	cvmId  string
	logger *slog.Logger
	vm.StateMachine
}

type qemuInfo struct {
	VirtualSize int64 `json:"virtual-size"`
}

func NewVM(config any, cvmId string, logger *slog.Logger) vm.VM {
	return &qemuVM{
		vmi:          config.(VMInfo),
		cvmId:        cvmId,
		StateMachine: vm.NewStateMachine(),
		logger:       logger,
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
	v.vmi.Config.SEVSNPConfig.ID = fmt.Sprintf("%s-%s", v.vmi.Config.SEVSNPConfig.ID, id)
	v.vmi.Config.TDXConfig.ID = fmt.Sprintf("%s-%s", v.vmi.Config.TDXConfig.ID, id)

	if !v.vmi.Config.EnableSEVSNP && !v.vmi.Config.EnableTDX {
		// Copy firmware vars file.
		srcFile := v.vmi.Config.OVMFVarsConfig.File
		dstFile := fmt.Sprintf("%s/%s-%s.fd", tmpDir, firmwareVars, id)
		err = internal.CopyFile(srcFile, dstFile)
		if err != nil {
			return err
		}
		v.vmi.Config.OVMFVarsConfig.File = dstFile
	}

	if v.vmi.Config.EnableDisk {
		sizeGB, err := GetVirtualSizeGB(v.vmi.Config.SrcFile)
		if err != nil {
			return err
		}

		dstDiskFile := fmt.Sprintf("%s/%s-%s.qcow2", tmpDir, diskDstName, id)
		sizeArg := fmt.Sprintf("%dG", sizeGB)

		cmd := exec.Command("qemu-img", "create", "-f", "qcow2", dstDiskFile, sizeArg)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("qemu-img create failed: %w: %s", err, string(out))
		}
		v.vmi.Config.DstFile = dstDiskFile
	}

	exe, args, err := v.executableAndArgs()
	if err != nil {
		return err
	}

	v.cmd = exec.Command(exe, args...)
	v.cmd.Stdout = &vm.Stdout{StateMachine: v.StateMachine, Logger: v.logger.With(slog.String("cvm", v.cvmId))}
	v.cmd.Stderr = &vm.Stderr{StateMachine: v.StateMachine, Logger: v.logger.With(slog.String("cvm", v.cvmId))}

	return v.cmd.Start()
}

func (v *qemuVM) Stop() error {
	defer func() {
		err := v.StateMachine.Transition(manager.StopComputationRun)
		if err != nil {
			return
		}
	}()
	err := v.cmd.Process.Signal(syscall.SIGTERM)
	if err != nil {
		return fmt.Errorf("failed to send SIGTERM: %v", err)
	}

	if v.vmi.Config.CertsMount != "" {
		if err := os.RemoveAll(v.vmi.Config.CertsMount); err != nil {
			return fmt.Errorf("failed to remove certs mount: %v", err)
		}
	}

	if v.vmi.Config.EnvMount != "" {
		if err := os.RemoveAll(v.vmi.Config.EnvMount); err != nil {
			return fmt.Errorf("failed to remove env mount: %v", err)
		}
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

func (v *qemuVM) GetConfig() any {
	return v.vmi
}

func SEVSNPEnabled(cpuinfo, kernelParam string) bool {
	return strings.Contains(cpuinfo, "sev_snp") && strings.TrimSpace(kernelParam) == "Y"
}

func TDXEnabled(cpuinfo, kernelParam string) bool {
	return strings.Contains(cpuinfo, "tdx_host_platform") && strings.TrimSpace(kernelParam) == "Y"
}

func SEVSNPEnabledOnHost() bool {
	cpuinfo, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false
	}

	kernelParam, err := os.ReadFile("/sys/module/kvm_amd/parameters/sev_snp")
	if err != nil {
		return false
	}

	return SEVSNPEnabled(string(cpuinfo), string(kernelParam))
}

func TDXEnabledOnHost() bool {
	cpuinfo, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false
	}

	kernelParam, err := os.ReadFile("/sys/module/kvm_intel/parameters/tdx")
	if err != nil {
		return false
	}

	return TDXEnabled(string(cpuinfo), string(kernelParam))
}

func GetVirtualSizeBytes(path string) (int64, error) {
	cmd := exec.Command("qemu-img", "info", "--output=json", path)
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("qemu-img info failed: %w", err)
	}

	var info qemuInfo
	if err := json.Unmarshal(out, &info); err != nil {
		return 0, fmt.Errorf("failed to parse qemu-img JSON: %w", err)
	}

	if info.VirtualSize <= 0 {
		return 0, fmt.Errorf("invalid virtual size: %d", info.VirtualSize)
	}

	return info.VirtualSize, nil
}

func GetVirtualSizeGB(path string) (int, error) {
	bytes, err := GetVirtualSizeBytes(path)
	if err != nil {
		return 0, err
	}

	gb := (bytes + (1<<30 - 1)) >> 30
	return int(gb), nil
}
