// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ultravioletrs/cocos/manager/qemu"
	"github.com/ultravioletrs/cocos/manager/vm"
	"github.com/ultravioletrs/cocos/manager/vm/mocks"
	"github.com/ultravioletrs/cocos/pkg/attestation/corim"
)

func CreateDummyCoRIMFile(t *testing.T, content []byte) string {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "policy.corim")
	err := os.WriteFile(filePath, content, 0o644)
	assert.NoError(t, err)
	return tempDir
}

func TestFetchAttestationPolicy(t *testing.T) {
	testCases := []struct {
		name             string
		computationId    string
		enableSEVSNP     bool
		expectedPlatform string
		expectedError    string
	}{
		{
			name:             "Valid CoRIM Generation (TDX Default)",
			computationId:    "valid-computation",
			enableSEVSNP:     false,
			expectedPlatform: "tdx-corim",
		},
		{
			name:             "Valid CoRIM Generation (SNP)",
			computationId:    "valid-computation-snp",
			enableSEVSNP:     true,
			expectedPlatform: "snp-corim",
		},
		{
			name:          "Invalid computation ID",
			computationId: "non-existent",
			enableSEVSNP:  false,
			expectedError: "computationId non-existent not found",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ms := &managerService{
				vms: make(map[string]vm.VM),
				qemuCfg: qemu.Config{
					EnableSEVSNP: tc.enableSEVSNP,
					CPU:          "EPYC",
				},
				attestationPolicyBinaryPath: "/tmp/test",
			}

			mockVM := new(mocks.VM)
			if tc.computationId != "non-existent" {
				// Mock GetConfig to return VMInfo with appropriate config
				vmInfo := qemu.VMInfo{
					Config: qemu.Config{
						EnableSEVSNP: tc.enableSEVSNP,
						CPU:          "EPYC",
					},
					LaunchTCB: 0,
				}
				mockVM.On("GetConfig").Return(vmInfo)
				ms.vms[tc.computationId] = mockVM
			}

			result, err := ms.FetchAttestationPolicy(context.Background(), tc.computationId)

			if tc.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)

				// Verify generated content is valid CoRIM
				manifest, err := corim.ParseCorim(result)
				assert.NoError(t, err, "Result should be valid CoRIM CBOR")

				// Verify Platform ID matches
				// Corim ID is usually the first byte array in Corim struct (ID)
				// Corim.ID is []byte
				assert.True(t, bytes.Equal(manifest.ID, []byte(tc.expectedPlatform)), "CoRIM ID should match platform tag")
			}
		})
	}
}
