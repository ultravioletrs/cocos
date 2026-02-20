// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ultravioletrs/cocos/manager/qemu"
	"github.com/ultravioletrs/cocos/manager/vm"
	"github.com/ultravioletrs/cocos/manager/vm/mocks"
	"github.com/ultravioletrs/cocos/pkg/attestation/policy"
)

func TestFetchAttestationPolicy(t *testing.T) {
	testCases := []struct {
		name           string
		computationId  string
		vmConfig       any
		expectedError  string
		expectedResult map[string]any
	}{
		{
			name:          "Valid SEV-SNP configuration",
			computationId: "sev-snp-computation",
			vmConfig: qemu.VMInfo{
				Config: qemu.Config{
					EnableSEVSNP: true,
					SMPCount:     2,
					CPU:          "EPYC",
				},
				LaunchTCB: 0,
			},
			expectedError: "open /dev/sev:",
		},
		{
			name:          "Invalid computation ID",
			computationId: "non-existent",
			vmConfig:      qemu.VMInfo{Config: qemu.Config{}, LaunchTCB: 0},
			expectedError: "computationId non-existent not found",
		},
		{
			name:          "Invalid config type",
			computationId: "invalid-config",
			vmConfig:      struct{}{},
			expectedError: "failed to cast config to qemu.VMInfo",
		},
		{
			name:          "Valid TDX configuration",
			computationId: "tdx-computation",
			vmConfig: qemu.VMInfo{
				Config: qemu.Config{
					EnableTDX: true,
					SMPCount:  2,
					CPU:       "Intel",
				},
				LaunchTCB: 0,
			},
			expectedError: "",
			expectedResult: map[string]interface{}{
				"policy": map[string]interface{}{
					"headerPolicy": map[string]interface{}{"qeVendorId": "AQIDBAUGBwgJCgsMDQ4PEA=="},
					"tdQuoteBodyPolicy": map[string]interface{}{
						"minimumTeeTcbSvn": "ERITFBUWFxgZGhscHR4fIA==",
						"mrSeam":           "ISIjJA==",
						"mrTd":             "NTY3OA==",
						"rtmrs": []interface{}{
							"QUJDRA==",
							"RUZHSA==",
							"SUpLTA==",
							"TU5PUA==",
						},
						"tdAttributes": "JSYnKCkqKyw=",
						"xfam":         "LS4vMDEyMzQ=",
					},
				},
				"rootOfTrust": map[string]interface{}{
					"checkCrl":      true,
					"getCollateral": true,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ms := &managerService{
				vms:               make(map[string]vm.VM),
				pcrValuesFilePath: "",
				qemuCfg: qemu.Config{
					CPU: "host",
				},
				tdxPolicyConfig: &policy.TDXConfig{
					SGXVendorID:  [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
					MinTdxSvn:    [16]byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20},
					MrSeam:       []byte{0x21, 0x22, 0x23, 0x24},
					TdAttributes: [8]byte{0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c},
					Xfam:         [8]byte{0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34},
					MrTd:         []byte{0x35, 0x36, 0x37, 0x38},
					RTMR: [4][]byte{
						{0x41, 0x42, 0x43, 0x44},
						{0x45, 0x46, 0x47, 0x48},
						{0x49, 0x4a, 0x4b, 0x4c},
						{0x4d, 0x4e, 0x4f, 0x50},
					},
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

				var attestationPolicy map[string]any
				err = json.Unmarshal(result, &attestationPolicy)
				assert.NoError(t, err)

				assert.Equal(t, tc.expectedResult, attestationPolicy)
			}
		})
	}
}
