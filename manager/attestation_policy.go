// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build !embed

package manager

import (
	"context"
	"fmt"

	"github.com/ultravioletrs/cocos/manager/qemu"
	"github.com/ultravioletrs/cocos/pkg/attestation/policy"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
)

func (ms *managerService) FetchAttestationPolicy(_ context.Context, computationId string) ([]byte, error) {
	ms.mu.Lock()
	vm, exists := ms.vms[computationId]
	ms.mu.Unlock()
	if !exists {
		return nil, fmt.Errorf("computationId %s not found", computationId)
	}

	vmi, ok := vm.GetConfig().(qemu.VMInfo)
	if !ok {
		return nil, fmt.Errorf("failed to cast config to qemu.VMInfo")
	}

	var err error
	var attestPolicy []byte
	switch {
	case vmi.Config.EnableSEVSNP:
		config, errp := policy.FetchSEVSNPAttestationPolicy(
			ms.sevsnpPolicy,
			ms.pcrValuesFilePath,
			ms.qemuCfg.IGVMConfig.File,
			ms.igvmMeasurementBinaryPath,
			ms.qemuCfg.EnableHostData,
			ms.qemuCfg.HostData)
		if errp != nil {
			return nil, errp
		}

		config.Config.Policy.MinimumLaunchTcb = vmi.LaunchTCB

		attestPolicy, err = vtpm.ConvertPolicyToJSON(config)
	case vmi.Config.EnableTDX:
		attestPolicy, err = policy.FetchTDXAttestationPolicy(ms.tdxPolicyConfig)
	}

	if err != nil {
		return nil, err
	}

	return attestPolicy, nil
}
