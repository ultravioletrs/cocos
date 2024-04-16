// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package qemu

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/gofrs/uuid"
	"github.com/ultravioletrs/cocos/internal"
)

const (
	firmwareVars = "OVMF_VARS"
	KernelFile   = "bzImage"
	rootfsFile   = "rootfs.cpio"
)

func CreateVM(ctx context.Context, cfg Config) (*exec.Cmd, error) {
	// Create unique emu device identifiers
	id, err := uuid.NewV4()
	if err != nil {
		return &exec.Cmd{}, err
	}
	qemuCfg := cfg
	qemuCfg.NetDevConfig.ID = fmt.Sprintf("%s-%s", qemuCfg.NetDevConfig.ID, id)
	qemuCfg.SevConfig.ID = fmt.Sprintf("%s-%s", qemuCfg.SevConfig.ID, id)

	if !cfg.KernelHash {
		// Copy firmware vars file
		srcFile := qemuCfg.OVMFVarsConfig.File
		dstFile := fmt.Sprintf("%s/%s-%s.fd", cfg.TmpFileLoc, firmwareVars, id)
		err = internal.CopyFile(srcFile, dstFile)
		if err != nil {
			return &exec.Cmd{}, err
		}
		qemuCfg.OVMFVarsConfig.File = dstFile
	}

	// Copy img files
	srcFile := qemuCfg.DiskImgConfig.KernelFile
	dstFile := fmt.Sprintf("%s/%s-%s", cfg.TmpFileLoc, KernelFile, id)
	err = internal.CopyFile(srcFile, dstFile)
	if err != nil {
		return &exec.Cmd{}, err
	}
	qemuCfg.DiskImgConfig.KernelFile = dstFile

	srcFile = qemuCfg.DiskImgConfig.RootFsFile
	dstFile = fmt.Sprintf("%s/%s-%s.gz", cfg.TmpFileLoc, rootfsFile, id)
	err = internal.CopyFile(srcFile, dstFile)
	if err != nil {
		return &exec.Cmd{}, err
	}
	qemuCfg.DiskImgConfig.RootFsFile = dstFile

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
	exe, err := exec.LookPath(cfg.QemuBinPath)
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
