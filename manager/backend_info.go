// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build !embed
// +build !embed

package manager

import (
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

func (ms *managerService) FetchBackendInfo() ([]byte, error) {
	cmd := exec.Command("sudo", fmt.Sprintf("%s/backend_info", ms.backendMeasurementBinaryPath), "--policy", "1966081")

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
	if ms.qemuCfg.EnableSEV {
		measurement, err = guest.CalcLaunchDigest(guest.SEV, ms.qemuCfg.SMPCount, uint64(cpuid.CpuSigs[ms.qemuCfg.CPU]), ms.qemuCfg.OVMFCodeConfig.File, ms.qemuCfg.KernelFile, ms.qemuCfg.RootFsFile, qemu.KernelCommandLine, defGuestFeatures, "", vmmtypes.QEMU, false, "", 0)
		if err != nil {
			return nil, err
		}
	} else if ms.qemuCfg.EnableSEVSNP {
		measurement, err = guest.CalcLaunchDigest(guest.SEV_SNP, ms.qemuCfg.SMPCount, uint64(cpuid.CpuSigs[ms.qemuCfg.CPU]), ms.qemuCfg.OVMFCodeConfig.File, ms.qemuCfg.KernelFile, ms.qemuCfg.RootFsFile, qemu.KernelCommandLine, defGuestFeatures, "", vmmtypes.QEMU, false, "", 0)
		if err != nil {
			return nil, err
		}
	}
	backendInfo.SNPPolicy.Measurement = measurement

	f, err = json.MarshalIndent(backendInfo, "", " ")
	if err != nil {
		return nil, err
	}

	return f, nil
}
