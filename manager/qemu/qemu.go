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

	cmdLine := fmt.Sprintf("%s %s", prg, strings.Join(args, " "))
	fmt.Println(cmdLine)

	cmd, err := internal.RunCmdStart(prg, args...)
	if err != nil {
		return nil, err
	}

	return cmd, nil
}
