// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package vm

import (
	"fmt"
	"os/exec"

	"github.com/gofrs/uuid"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/internal"
	"github.com/ultravioletrs/cocos/manager/qemu"
	"github.com/ultravioletrs/cocos/pkg/manager"
)

const (
	firmwareVars = "OVMF_VARS"
	KernelFile   = "bzImage"
	rootfsFile   = "rootfs.cpio"
)

// VM represents a virtual machine.
//
//go:generate mockery --name VM --output=./mocks --filename vm.go --quiet --note "Copyright (c) Ultraviolet \n // SPDX-License-Identifier: Apache-2.0"
type VM interface {
	Start() error
	Stop() error
	SendAgentConfig(ac agent.Computation) error
}

type vm struct {
	config        qemu.Config
	cmd           *exec.Cmd
	logsChan      chan *manager.ClientStreamMessage
	computationId string
}

//go:generate mockery --name VMFactory --output=./mocks --filename vm_factory.go --quiet --note "Copyright (c) Ultraviolet \n // SPDX-License-Identifier: Apache-2.0"
type VMFactory func(config qemu.Config, logsChan chan *manager.ClientStreamMessage, computationId string) VM

func NewVM(config qemu.Config, logsChan chan *manager.ClientStreamMessage, computationId string) VM {
	return &vm{
		config:        config,
		logsChan:      logsChan,
		computationId: computationId,
	}
}

func (v *vm) Start() error {
	// Create unique qemu device identifiers
	id, err := uuid.NewV4()
	if err != nil {
		return err
	}
	qemuCfg := v.config
	qemuCfg.NetDevConfig.ID = fmt.Sprintf("%s-%s", qemuCfg.NetDevConfig.ID, id)
	qemuCfg.SevConfig.ID = fmt.Sprintf("%s-%s", qemuCfg.SevConfig.ID, id)

	if !v.config.KernelHash {
		// Copy firmware vars file
		srcFile := qemuCfg.OVMFVarsConfig.File
		dstFile := fmt.Sprintf("%s/%s-%s.fd", v.config.TmpFileLoc, firmwareVars, id)
		err = internal.CopyFile(srcFile, dstFile)
		if err != nil {
			return err
		}
		qemuCfg.OVMFVarsConfig.File = dstFile
	}

	// Copy img files
	srcFile := qemuCfg.DiskImgConfig.KernelFile
	dstFile := fmt.Sprintf("%s/%s-%s", v.config.TmpFileLoc, KernelFile, id)
	err = internal.CopyFile(srcFile, dstFile)
	if err != nil {
		return err
	}
	qemuCfg.DiskImgConfig.KernelFile = dstFile

	srcFile = qemuCfg.DiskImgConfig.RootFsFile
	dstFile = fmt.Sprintf("%s/%s-%s.gz", v.config.TmpFileLoc, rootfsFile, id)
	err = internal.CopyFile(srcFile, dstFile)
	if err != nil {
		return err
	}
	qemuCfg.DiskImgConfig.RootFsFile = dstFile

	exe, args, err := v.executableAndArgs()
	if err != nil {
		return err
	}

	v.cmd = exec.Command(exe, args...)
	v.cmd.Stdout = &stdout{logsChan: v.logsChan, computationId: v.computationId}
	v.cmd.Stderr = &stderr{logsChan: v.logsChan, computationId: v.computationId}

	return v.cmd.Start()
}

func (v *vm) Stop() error {
	return v.cmd.Process.Kill()
}

func (v *vm) executableAndArgs() (string, []string, error) {
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
