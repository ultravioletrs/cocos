// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build !embed
// +build !embed

package manager

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"

	"github.com/google/go-sev-guest/proto/check"
	"github.com/ultravioletrs/cocos/manager/qemu"
	"github.com/virtee/sev-snp-measure-go/cpuid"
	"github.com/virtee/sev-snp-measure-go/guest"
	"github.com/virtee/sev-snp-measure-go/vmmtypes"
	"google.golang.org/protobuf/encoding/protojson"
)

const defGuestFeatures = 0x1

func (ms *managerService) FetchAttestationPolicy(_ context.Context, computationId string) ([]byte, error) {
	cmd := exec.Command("sudo", fmt.Sprintf("%s/attestation_policy", ms.attestationPolicyBinaryPath), "--policy", "196608")

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

	f, err := os.ReadFile("./attestation_policy.json")
	if err != nil {
		return nil, err
	}

	var attestationPolicy check.Config

	if err = protojson.Unmarshal(f, &attestationPolicy); err != nil {
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
	if measurement != nil {
		attestationPolicy.Policy.Measurement = measurement
	}

	if config.HostData != "" {
		hostData, err := base64.StdEncoding.DecodeString(config.HostData)
		if err != nil {
			return nil, err
		}
		attestationPolicy.Policy.HostData = hostData
	}

	f, err = protojson.Marshal(&attestationPolicy)
	if err != nil {
		return nil, err
	}

	return f, nil
}
