package qemu

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/mainflux/mainflux/logger"
	"github.com/ultravioletrs/manager/internal"
)

// RunQemuVM runs a QEMU virtual machine: constructs the QEMU command line arguments by executing the launch-qemu.sh,
// extracts the QEMU command and its arguments, and starts the QEMU process
func RunQemuVM(cfg Config, logger logger.Logger) (*exec.Cmd, error) {
	prg := "/usr/bin/qemu-system-x86_64"
	args := constructQemuCmd(cfg)

	if cfg.UseSudo {
		args = append([]string{prg}, args...)
		prg = "sudo"
	}

	logger.Info(fmt.Sprintf("%s %s", prg, strings.Join(args, " ")))

	cmd, err := internal.RunCmdStart(prg, args...)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to run qemu command: %v", err))
		return nil, err
	}

	return cmd, nil
}
