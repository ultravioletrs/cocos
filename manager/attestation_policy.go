// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build !embed

package manager

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"

	"github.com/ultravioletrs/cocos/manager/qemu"
	"github.com/ultravioletrs/cocos/pkg/attestation/generator"
	"github.com/ultravioletrs/cocos/pkg/attestation/igvmmeasure"
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

	// Determine platform
	platform := "tdx"
	var measurement string
	var hostData string
	var launchTCB uint64

	if vmi.Config.EnableSEVSNP {
		platform = "snp"

		// Calculate IGVM measurement
		igvmMeasurementBinaryPath := fmt.Sprintf("%s/igvmmeasure", ms.attestationPolicyBinaryPath)

		var stdoutBuffer bytes.Buffer
		var stderrBuffer bytes.Buffer

		stdout := bufio.NewWriter(&stdoutBuffer)
		stderr := bufio.NewWriter(&stderrBuffer)

		igvmMeasurement, err := igvmmeasure.NewIgvmMeasurement(igvmMeasurementBinaryPath, stderr, stdout)
		if err != nil {
			return nil, fmt.Errorf("failed to create IGVM measurement: %w", err)
		}

		err = igvmMeasurement.Run(ms.qemuCfg.IGVMConfig.File)
		if err != nil {
			return nil, fmt.Errorf("failed to run IGVM measurement: %w", err)
		}

		// Convert measurement bytes to hex string
		measurement = fmt.Sprintf("%x", stdoutBuffer.Bytes())

		// Extract host data if enabled
		if vmi.Config.SEVSNPConfig.EnableHostData {
			hostDataBytes, err := base64.StdEncoding.DecodeString(vmi.Config.SEVSNPConfig.HostData)
			if err != nil {
				return nil, fmt.Errorf("failed to decode host data: %w", err)
			}
			hostData = fmt.Sprintf("%x", hostDataBytes)
		}

		// Use launch TCB from VM info
		launchTCB = vmi.LaunchTCB
	}

	opts := generator.Options{
		Platform:    platform,
		Measurement: measurement,
		HostData:    hostData,
		LaunchTCB:   launchTCB,
		Product:     ms.qemuCfg.CPU, // Use CPU as product identifier
		SigningKey:  ms.signingKey,
	}

	// Generate CoRIM
	return generator.GenerateCoRIM(opts)
}
