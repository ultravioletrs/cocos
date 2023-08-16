package qemu

import (
	"os/exec"

	"github.com/ultravioletrs/manager/internal"
)

const qemuRelPath = "qemu-system-x86_64"

// RunQemuVM runs a QEMU virtual machine: constructs the QEMU command line and starts the QEMU process
func RunQemuVM(exe string, args []string) (*exec.Cmd, error) {
	cmd, err := internal.RunCmdStart(exe, args...)
	if err != nil {
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
