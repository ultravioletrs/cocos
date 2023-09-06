package qemu

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/gofrs/uuid"
	"github.com/ultravioletrs/manager/internal"
)

const qemuRelPath = "qemu-system-x86_64"
const firmwareVars = "OVMF_VARS"
const qcow2Img = "focal-server-cloudimg-amd64"

func CreateVM(ctx context.Context, cfg Config) (*exec.Cmd, error) {
	// create unique emu device identifiers
	id, err := uuid.NewV4()
	if err != nil {
		return &exec.Cmd{}, err
	}
	qemuCfg := cfg
	qemuCfg.NetDevConfig.ID = fmt.Sprintf("%s-%s", qemuCfg.NetDevConfig.ID, id)
	qemuCfg.DiskImgConfig.ID = fmt.Sprintf("%s-%s", qemuCfg.DiskImgConfig.ID, id)
	qemuCfg.VirtioScsiPciConfig.ID = fmt.Sprintf("%s-%s", qemuCfg.VirtioScsiPciConfig.ID, id)
	qemuCfg.SevConfig.ID = fmt.Sprintf("%s-%s", qemuCfg.SevConfig.ID, id)

	// copy firmware vars file
	srcFile := qemuCfg.OVMFVarsConfig.File
	dstFile := fmt.Sprintf("%s/%s-%s.fd", cfg.TmpFileLoc, firmwareVars, id)
	err = internal.CopyFile(srcFile, dstFile)
	if err != nil {
		return &exec.Cmd{}, err
	}
	qemuCfg.OVMFVarsConfig.File = dstFile

	// copy qcow2 img file
	srcFile = qemuCfg.DiskImgConfig.File
	dstFile = fmt.Sprintf("%s/%s-%s.img", cfg.TmpFileLoc, qcow2Img, id)
	err = internal.CopyFile(srcFile, dstFile)
	if err != nil {
		return &exec.Cmd{}, err
	}
	qemuCfg.DiskImgConfig.File = dstFile

	exe, args, err := ExecutableAndArgs(qemuCfg)
	if err != nil {
		return &exec.Cmd{}, err
	}
	cmd, err := runQemuVM(exe, args)
	if err != nil {
		return cmd, err
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

func runQemuVM(exe string, args []string) (*exec.Cmd, error) {
	cmd, err := internal.RunCmdStart(exe, args...)
	if err != nil {
		return nil, err
	}

	return cmd, nil
}
