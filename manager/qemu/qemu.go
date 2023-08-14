package qemu

import (
	"fmt"
	"os/exec"

	"github.com/mainflux/mainflux/logger"
	"github.com/ultravioletrs/manager/internal"
)

const qemuRelPath = "qemu-system-x86_64"

// RunQemuVM runs a QEMU virtual machine: constructs the QEMU command line and starts the QEMU process
func RunQemuVM(exe string, args []string, logger logger.Logger) (*exec.Cmd, error) {
	cmd, err := internal.RunCmdStart(exe, args...)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to run qemu command: %v", err))
		return nil, err
	}

	return cmd, nil
}

func ExecutableAndArgs(cfg Config) (string, []string, error) {
	exe, err := exec.LookPath(qemuRelPath)
	if err != nil {
		return "", nil, err
	}

	args := constructQemuArgs(cfg)

	if cfg.UseSudo {
		args = append([]string{exe}, args...)
		exe = "sudo"
	}

	return exe, args, nil
}
