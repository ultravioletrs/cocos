package qemu

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/mainflux/mainflux/logger"
	"github.com/ultravioletrs/manager/internal"
)

const qemuRelPath = "qemu-system-x86_64"

// RunQemuVM runs a QEMU virtual machine: constructs the QEMU command line and starts the QEMU process
func RunQemuVM(cfg Config, logger logger.Logger) (*exec.Cmd, error) {
	qemuAbsPath, err := exec.LookPath(qemuRelPath)
	if err != nil {
		logger.Error(fmt.Sprintf("qemu-system-x86_64 not found: %v", err))
		return nil, err
	}
	args := constructQemuCmd(cfg)

	if cfg.UseSudo {
		args = append([]string{qemuAbsPath}, args...)
		qemuAbsPath = "sudo"
	}

	logger.Info(fmt.Sprintf("%s %s", qemuAbsPath, strings.Join(args, " ")))

	cmd, err := internal.RunCmdStart(qemuAbsPath, args...)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to run qemu command: %v", err))
		return nil, err
	}

	return cmd, nil
}
