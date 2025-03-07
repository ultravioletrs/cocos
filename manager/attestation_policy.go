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
	"strconv"
	"strings"

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

	vmi, ok := vm.GetConfig().(qemu.VMInfo)
	if !ok {
		return nil, fmt.Errorf("failed to cast config to qemu.VMInfo")
	}

	ms.ap.Lock()
	_, err := cmd.Output()
	ms.ap.Unlock()
	if err != nil {
		return nil, err
	}

	ms.ap.Lock()
	f, err := os.ReadFile("./attestation_policy.json")
	ms.ap.Unlock()
	if err != nil {
		return nil, err
	}

	var attestationPolicy check.Config

	if err = protojson.Unmarshal(f, &attestationPolicy); err != nil {
		return nil, err
	}

	var measurement []byte
	switch {
	case vmi.Config.EnableSEV:
		measurement, err = guest.CalcLaunchDigest(guest.SEV, vmi.Config.SMPCount, uint64(cpuid.CpuSigs[ms.qemuCfg.CPU]), vmi.Config.OVMFCodeConfig.File, vmi.Config.KernelFile, vmi.Config.RootFsFile, strconv.Quote(qemu.KernelCommandLine), defGuestFeatures, "", vmmtypes.QEMU, false, "", 0)
		if err != nil {
			return nil, err
		}
	case vmi.Config.EnableSEVSNP:
		args := []string{}
		args = append(args, fmt.Sprintf("%s/igvmmeasure", ms.attestationPolicyBinaryPath))
		args = append(args, ms.qemuCfg.IGVMConfig.File)
		args = append(args, "measure")
		args = append(args, "-b")

		igvm_measure_cmd := exec.Command("sudo", args...)

		out, err := igvm_measure_cmd.Output()
		if err != nil {
			return nil, err
		}

		outputString := string(out)

		lines := strings.Split(strings.TrimSpace(outputString), "\n")

		if len(lines) == 1 {
			measurement = out
		} else {
			return nil, fmt.Errorf("error: %s", outputString)
		}
	}

	if measurement != nil {
		attestationPolicy.Policy.Measurement = measurement
	}

	if vmi.Config.SevConfig.EnableHostData {
		hostData, err := base64.StdEncoding.DecodeString(vmi.Config.SevConfig.HostData)
		if err != nil {
			return nil, err
		}
		attestationPolicy.Policy.HostData = hostData
	}

	attestationPolicy.Policy.MinimumLaunchTcb = vmi.LaunchTCB

	f, err = protojson.Marshal(&attestationPolicy)
	if err != nil {
		return nil, err
	}

	return f, nil
}
