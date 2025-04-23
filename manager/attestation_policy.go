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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/go-sev-guest/proto/check"
	"github.com/ultravioletrs/cocos/manager/qemu"
	attestations "github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/cmdconfig"

	"github.com/virtee/sev-snp-measure-go/cpuid"
	"github.com/virtee/sev-snp-measure-go/guest"
	"github.com/virtee/sev-snp-measure-go/vmmtypes"
)

const defGuestFeatures = 0x1

func (ms *managerService) FetchAttestationPolicy(_ context.Context, computationId string) ([]byte, error) {
	var stderrBuffer bytes.Buffer
	options := []string{"--policy", "196608"}

	if ms.pcrValuesFilePath != "" {
		pcrValues := []string{"--pcr", ms.pcrValuesFilePath}
		options = append(options, pcrValues...)
	}

	stderr := bufio.NewWriter(&stderrBuffer)

	attestPolicyCmd, err := cmdconfig.NewCmdConfig("sudo", options, stderr)
	if err != nil {
		return nil, err
	}

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
	stdOutByte, err := attestPolicyCmd.Run(ms.attestationPolicyBinaryPath)
	ms.ap.Unlock()
	if err != nil {
		return nil, err
	}

	attestationPolicy := attestations.Config{Config: &check.Config{RootOfTrust: &check.RootOfTrust{}, Policy: &check.Policy{}}, PcrConfig: &attestations.PcrConfig{}}

	if err = attestations.ReadAttestationPolicyFromByte(stdOutByte, &attestationPolicy); err != nil {
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
		stderr := bufio.NewWriter(&stderrBuffer)
		options := cmdconfig.IgvmMeasureOptions

		igvmMeasurement, err := cmdconfig.NewCmdConfig(ms.igvmMeasurementBinaryPath, options, stderr)
		if err != nil {
			return nil, err
		}

		outputByte, err := igvmMeasurement.Run(ms.qemuCfg.IGVMConfig.File)
		if err != nil {
			return nil, err
		}

		outputString := string(outputByte)
		lines := strings.Split(strings.TrimSpace(outputString), "\n")

		if len(lines) == 1 {
			outputString = strings.TrimSpace(outputString)
			outputString = strings.ToLower(outputString)
		} else {
			return nil, fmt.Errorf("error: %s", outputString)
		}

		measurement, err = hex.DecodeString(outputString)
		if err != nil {
			return nil, err
		}
	}

	if measurement != nil {
		attestationPolicy.Config.Policy.Measurement = measurement
	}

	if vmi.Config.SevConfig.EnableHostData {
		hostData, err := base64.StdEncoding.DecodeString(vmi.Config.SevConfig.HostData)
		if err != nil {
			return nil, err
		}
		attestationPolicy.Config.Policy.HostData = hostData
	}

	attestationPolicy.Config.Policy.MinimumLaunchTcb = vmi.LaunchTCB

	f, err := json.MarshalIndent(attestationPolicy, "", " ")
	if err != nil {
		return nil, err
	}

	return f, nil
}
