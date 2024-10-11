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

func createDummyBackendInfoBinary(t *testing.T, behavior string) string {
	var content []byte
	switch behavior {
	case "success":
		content = []byte(`#!/bin/sh
echo '{"snp_policy": {"measurement": null, "host_data": null}}' > backend_info.json
`)
	case "fail":
		content = []byte(`#!/bin/sh
echo "Error: Failed to execute backend_info" >&2
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
	binaryPath := filepath.Join(tempDir, "backend_info")
	err := os.WriteFile(binaryPath, content, 0755)
	assert.NoError(t, err)
	return tempDir
}

func TestFetchBackendInfo(t *testing.T) {
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
			vmConfig: qemu.Config{
				EnableSEV: true,
				SMPCount:  2,
				CPU:       "EPYC",
				OVMFCodeConfig: qemu.OVMFCodeConfig{
					File: "/path/to/OVMF_CODE.fd",
				},
			},
			expectedError: "open /path/to/OVMF_CODE.fd: no such file or directory",
		},
		{
			name:           "Valid SEV-SNP configuration",
			computationId:  "sev-snp-computation",
			binaryBehavior: "success",
			vmConfig: qemu.Config{
				EnableSEVSNP: true,
				SMPCount:     4,
				CPU:          "EPYC-v2",
				OVMFCodeConfig: qemu.OVMFCodeConfig{
					File: "/path/to/OVMF_CODE_SNP.fd",
				},
			},
			expectedError: "open /path/to/OVMF_CODE_SNP.fd: no such file or director",
		},
		{
			name:           "Invalid computation ID",
			computationId:  "non-existent",
			binaryBehavior: "success",
			vmConfig:       qemu.Config{},
			expectedError:  "computationId non-existent not found",
		},
		{
			name:           "Invalid config type",
			computationId:  "invalid-config",
			binaryBehavior: "success",
			vmConfig:       struct{}{},
			expectedError:  "failed to cast config to qemu.Config",
		},
		{
			name:           "Binary execution failure",
			computationId:  "binary-fail",
			binaryBehavior: "fail",
			vmConfig: qemu.Config{
				EnableSEV: true,
			},
			expectedError: "exit status 1",
		},
		{
			name:           "JSON file not created",
			computationId:  "no-json",
			binaryBehavior: "no_json",
			vmConfig: qemu.Config{
				EnableSEV: true,
			},
			expectedError: "no such file or directory",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tempDir := createDummyBackendInfoBinary(t, tc.binaryBehavior)
			defer os.RemoveAll(tempDir)

			ms := &managerService{
				vms:                          make(map[string]vm.VM),
				backendMeasurementBinaryPath: tempDir,
				qemuCfg: qemu.Config{
					CPU: "EPYC",
				},
			}

			mockVM := new(mocks.VM)
			mockVM.On("GetConfig").Return(tc.vmConfig)

			if tc.computationId != "non-existent" {
				ms.vms[tc.computationId] = mockVM
			}

			result, err := ms.FetchBackendInfo(context.Background(), tc.computationId)

			if tc.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)

				var backendInfo map[string]interface{}
				err = json.Unmarshal(result, &backendInfo)
				assert.NoError(t, err)

				assert.Equal(t, tc.expectedResult, backendInfo)
			}

			if tc.binaryBehavior == "success" {
				os.Remove("backend_info.json")
			}
		})
	}
}
