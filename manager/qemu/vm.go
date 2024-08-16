// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package qemu

import (
	"fmt"
	"os/exec"

	"github.com/gofrs/uuid"
	"github.com/ultravioletrs/cocos/manager/vm"
	"github.com/ultravioletrs/cocos/pkg/manager"
)

const (
	firmwareVars = "OVMF_VARS"
	KernelFile   = "bzImage"
	rootfsFile   = "rootfs.cpio"
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

func (v *qemuVM) Start() error {
	// Create unique qemu device identifiers
	id, err := uuid.NewV4()
	if err != nil {
		return err
	}
	qemuCfg := v.config
	qemuCfg.NetDevConfig.ID = fmt.Sprintf("%s-%s", qemuCfg.NetDevConfig.ID, id)
	qemuCfg.SevConfig.ID = fmt.Sprintf("%s-%s", qemuCfg.SevConfig.ID, id)

	exe, args, err := v.executableAndArgs()
	if err != nil {
		return err
	}

	v.cmd = exec.Command(exe, args...)
	v.cmd.Stdout = &vm.Stdout{LogsChan: v.logsChan, ComputationId: v.computationId}
	v.cmd.Stderr = &vm.Stderr{LogsChan: v.logsChan, ComputationId: v.computationId}

	return v.cmd.Start()
}

func (v *qemuVM) Stop() error {
	return v.cmd.Process.Kill()
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
