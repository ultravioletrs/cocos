// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build !embed
// +build !embed

package manager

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"

	"github.com/ultravioletrs/cocos/cli"
	"github.com/ultravioletrs/cocos/manager/qemu"
	"github.com/virtee/sev-snp-measure-go/cpuid"
	"github.com/virtee/sev-snp-measure-go/guest"
	"github.com/virtee/sev-snp-measure-go/vmmtypes"
)

const defGuestFeatures = 0x1

func (ms *managerService) FetchBackendInfo(_ context.Context, computationId string) ([]byte, error) {
	cmd := exec.Command("sudo", fmt.Sprintf("%s/backend_info", ms.backendMeasurementBinaryPath), "--policy", "1966081")

	ms.mu.Lock()
	vm, exists := ms.vms[computationId]
	ms.mu.Unlock()
	if !exists {
		return nil, fmt.Errorf("computationId %s not found", computationId)
	}

	config, ok := vm.GetConfig().(qemu.Config)
	if !ok {
		return nil, fmt.Errorf("failed to cast config to qemu.Config")
	}

	_, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	f, err := os.ReadFile("./backend_info.json")
	if err != nil {
		return nil, err
	}

	var backendInfo cli.AttestationConfiguration

	if err = json.Unmarshal(f, &backendInfo); err != nil {
		return nil, err
	}

	var measurement []byte
	switch {
	case config.EnableSEV:
		measurement, err = guest.CalcLaunchDigest(guest.SEV, config.SMPCount, uint64(cpuid.CpuSigs[ms.qemuCfg.CPU]), config.OVMFCodeConfig.File, config.KernelFile, config.RootFsFile, qemu.KernelCommandLine, defGuestFeatures, "", vmmtypes.QEMU, false, "", 0)
		if err != nil {
			return nil, err
		}
	case config.EnableSEVSNP:
		measurement, err = guest.CalcLaunchDigest(guest.SEV_SNP, config.SMPCount, uint64(cpuid.CpuSigs[config.CPU]), config.OVMFCodeConfig.File, config.KernelFile, config.RootFsFile, qemu.KernelCommandLine, defGuestFeatures, "", vmmtypes.QEMU, false, "", 0)
		if err != nil {
			return nil, err
		}
	}
	if measurement == nil {
		backendInfo.SNPPolicy.Measurement = measurement
	}

	if config.HostData != "" {
		hostData, err := base64.StdEncoding.DecodeString(config.HostData)
		if err != nil {
			return nil, err
		}
		backendInfo.SNPPolicy.HostData = hostData
	}

	f, err = json.Marshal(backendInfo)
	if err != nil {
		return nil, err
	}

	return f, nil
}
