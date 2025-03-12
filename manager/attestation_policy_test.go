// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ultravioletrs/cocos/manager/qemu"
	"github.com/ultravioletrs/cocos/manager/vm"
	"github.com/ultravioletrs/cocos/manager/vm/mocks"
)

func CreateDummyAttestationPolicyBinary(t *testing.T, behavior string) string {
	var content []byte
	switch behavior {
	case "success":
		content = []byte(`#!/bin/sh
echo '{"pcr_values": {"sha256": null, "sha384": null}, "policy": {"measurement": null, "host_data": null}}'
`)
	case "fail":
		content = []byte(`#!/bin/sh
echo "Error: Failed to execute attestation policy" >&2
exit 1
`)
	case "no_json":
		content = []byte(`#!/bin/sh
echo 'No JSON file created'
`)
	default:
		t.Fatalf("Unknown behavior: %s", behavior)
	}

	tempDir := t.TempDir()
	binaryPath := filepath.Join(tempDir, "attestation_policy")
	err := os.WriteFile(binaryPath, content, 0o755)
	assert.NoError(t, err)
	return tempDir
}

func TestFetchAttestationPolicy(t *testing.T) {
	testCases := []struct {
		name           string
		computationId  string
		vmConfig       interface{}
		binaryBehavior string
		expectedError  string
		expectedResult map[string]interface{}
	}{
		{
			name:           "Valid SEV configuration",
			computationId:  "sev-computation",
			binaryBehavior: "success",
			vmConfig: qemu.VMInfo{
				Config: qemu.Config{
					EnableSEV:    true,
					EnableSEVSNP: false,
					SMPCount:     2,
					CPU:          "EPYC",
					OVMFCodeConfig: qemu.OVMFCodeConfig{
						File: "/path/to/OVMF_CODE.fd",
					},
				},
				LaunchTCB: 0,
			},
			expectedError: "open /path/to/OVMF_CODE.fd: no such file or directory",
		},
		{
			name:           "Invalid computation ID",
			computationId:  "non-existent",
			binaryBehavior: "success",
			vmConfig:       qemu.VMInfo{Config: qemu.Config{}, LaunchTCB: 0},
			expectedError:  "computationId non-existent not found",
		},
		{
			name:           "Invalid config type",
			computationId:  "invalid-config",
			binaryBehavior: "success",
			vmConfig:       struct{}{},
			expectedError:  "failed to cast config to qemu.VMInfo",
		},
		{
			name:           "Binary execution failure",
			computationId:  "binary-fail",
			binaryBehavior: "fail",
			vmConfig: qemu.VMInfo{
				Config: qemu.Config{
					EnableSEV: true,
				},
				LaunchTCB: 0,
			},
			expectedError: "exit status 1",
		},
		{
			name:           "JSON file not created",
			computationId:  "no-json",
			binaryBehavior: "no_json",
			vmConfig: qemu.VMInfo{
				Config: qemu.Config{
					EnableSEV: true,
				},
				LaunchTCB: 0,
			},
			expectedError: "failed to decode Attestation Policy file",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tempDir := CreateDummyAttestationPolicyBinary(t, tc.binaryBehavior)
			defer os.RemoveAll(tempDir)

			ms := &managerService{
				vms:                         make(map[string]vm.VM),
				attestationPolicyBinaryPath: tempDir,
				pcrValuesFilePath:           tempDir,
				qemuCfg: qemu.Config{
					CPU: "EPYC",
				},
			}

			mockVM := new(mocks.VM)
			mockVM.On("GetConfig").Return(tc.vmConfig)

			if tc.computationId != "non-existent" {
				ms.vms[tc.computationId] = mockVM
			}

			result, err := ms.FetchAttestationPolicy(context.Background(), tc.computationId)

			if tc.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)

				var attestationPolicy map[string]interface{}
				err = json.Unmarshal(result, &attestationPolicy)
				assert.NoError(t, err)

				assert.Equal(t, tc.expectedResult, attestationPolicy)
			}

			if tc.binaryBehavior == "success" {
				os.Remove("attestation_policy.json")
			}
		})
	}
}
