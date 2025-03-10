// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build !embed
// +build !embed

package manager

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/google/go-sev-guest/proto/check"
	"github.com/ultravioletrs/cocos/manager/qemu"
	"github.com/ultravioletrs/cocos/pkg/attestation/igvmmeasure"
	"github.com/virtee/sev-snp-measure-go/cpuid"
	"github.com/virtee/sev-snp-measure-go/guest"
	"github.com/virtee/sev-snp-measure-go/vmmtypes"
	"google.golang.org/protobuf/encoding/protojson"
)

const defGuestFeatures = 0x1

func (ms *managerService) FetchAttestationPolicy(_ context.Context, computationId string) ([]byte, error) {
	pcrValues := []string{"", ""}
	policyPath := fmt.Sprintf("%s/attestation_policy", ms.attestationPolicyBinaryPath)
	if ms.pcrValuesFilePath != "" {
		pcrValues = []string{"--pcr", ms.pcrValuesFilePath}
	}
	cmd := exec.Command("sudo", append([]string{policyPath, "--policy", "196608"}, pcrValues...)...)

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
		igvmMeasurementBinaryPath := fmt.Sprintf("%s/igvmmeasure", ms.attestationPolicyBinaryPath)

		var stdoutBuffer bytes.Buffer
		var stderrBuffer bytes.Buffer

		stdout := bufio.NewWriter(&stdoutBuffer)
		stderr := bufio.NewWriter(&stderrBuffer)

		igvmMeasurement, err := igvmmeasure.NewIgvmMeasurement(igvmMeasurementBinaryPath, stderr, stdout)
		if err != nil {
			return nil, err
		}

		err = igvmMeasurement.Run(ms.qemuCfg.IGVMConfig.File)
		if err != nil {
			return nil, err
		}

		measurement = stdoutBuffer.Bytes()
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
