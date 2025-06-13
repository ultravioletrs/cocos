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
	"fmt"
	"strconv"
	"strings"

	"github.com/google/go-sev-guest/proto/check"
	"github.com/ultravioletrs/cocos/manager/qemu"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/cmdconfig"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"github.com/virtee/sev-snp-measure-go/cpuid"
	"github.com/virtee/sev-snp-measure-go/guest"
	"github.com/virtee/sev-snp-measure-go/vmmtypes"
)

const defGuestFeatures = 0x1

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

	var attestPolicyCmd *cmdconfig.CmdConfig
	var err error
	switch {
	case vmi.Config.EnableSEVSNP:
		attestPolicyCmd, err = fetchSNPAttestationPolicy(ms)
	case vmi.Config.EnableTDX:
		attestPolicyCmd, err = fetchTDXAttestationPolicy(ms)
	}

	if err != nil {
		return nil, err
	}

	var stdOutByte []byte
	ms.ap.Lock()
	switch {
	case vmi.Config.EnableSEVSNP:
		stdOutByte, err = attestPolicyCmd.Run(ms.attestationPolicyBinaryPath)
	case vmi.Config.EnableTDX:
		stdOutByte, err = attestPolicyCmd.Run("")
	}
	ms.ap.Unlock()
	if err != nil {
		return nil, err
	}

	var policy []byte
	switch {
	case vmi.Config.EnableSEVSNP:
		policy, err = readSEVSNPPolicy(stdOutByte, ms, vmi)
	case vmi.Config.EnableTDX:
		policy = stdOutByte
		err = nil
	}
	if err != nil {
		return nil, err
	}

	return policy, nil
}

func fetchSNPAttestationPolicy(ms *managerService) (*cmdconfig.CmdConfig, error) {
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

	return attestPolicyCmd, nil
}

func fetchTDXAttestationPolicy(ms *managerService) (*cmdconfig.CmdConfig, error) {
	var stderrBuffer bytes.Buffer

	stderr := bufio.NewWriter(&stderrBuffer)

	attestPolicyCmd, err := cmdconfig.NewCmdConfig(ms.attestationPolicyBinaryPath, nil, stderr)
	if err != nil {
		return nil, err
	}

	return attestPolicyCmd, nil
}

func readSEVSNPPolicy(stdOutByte []byte, ms *managerService, vmi qemu.VMInfo) ([]byte, error) {
	attestationPolicy := attestation.Config{Config: &check.Config{RootOfTrust: &check.RootOfTrust{}, Policy: &check.Policy{}}, PcrConfig: &attestation.PcrConfig{}}

	if err := quoteprovider.ReadSEVSNPAttestationPolicyFromByte(stdOutByte, &attestationPolicy); err != nil {
		return nil, err
	}

	var stderrBuffer bytes.Buffer
	var measurement []byte
	var err error
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

	if vmi.Config.SEVConfig.EnableHostData {
		hostData, err := base64.StdEncoding.DecodeString(vmi.Config.SEVConfig.HostData)
		if err != nil {
			return nil, err
		}
		attestationPolicy.Config.Policy.HostData = hostData
	}

	attestationPolicy.Config.Policy.MinimumLaunchTcb = vmi.LaunchTCB

	f, err := attestation.ConvertAttestationPolicyToJSON(&attestationPolicy)
	if err != nil {
		return nil, err
	}

	return policy, nil
}
