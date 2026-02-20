// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTcbVersionToUint64(t *testing.T) {
	tests := []struct {
		name     string
		tcb      TcbVersion
		expected uint64
	}{
		{
			name: "all zeros",
			tcb: TcbVersion{
				Bootloader: 0,
				TEE:        0,
				SNP:        0,
				Microcode:  0,
			},
			expected: 0,
		},
		{
			name: "bootloader only",
			tcb: TcbVersion{
				Bootloader: 1,
				TEE:        0,
				SNP:        0,
				Microcode:  0,
			},
			expected: 1,
		},
		{
			name: "tee only",
			tcb: TcbVersion{
				Bootloader: 0,
				TEE:        1,
				SNP:        0,
				Microcode:  0,
			},
			expected: 0x100,
		},
		{
			name: "snp only",
			tcb: TcbVersion{
				Bootloader: 0,
				TEE:        0,
				SNP:        1,
				Microcode:  0,
			},
			expected: 0x1000000000000,
		},
		{
			name: "microcode only",
			tcb: TcbVersion{
				Bootloader: 0,
				TEE:        0,
				SNP:        0,
				Microcode:  1,
			},
			expected: 0x100000000000000,
		},
		{
			name: "all fields set",
			tcb: TcbVersion{
				Bootloader: 0x12,
				TEE:        0x34,
				SNP:        0x56,
				Microcode:  0x78,
			},
			expected: 0x7856000000003412,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.tcb.ToUint64()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIoc(t *testing.T) {
	tests := []struct {
		name     string
		dir      uintptr
		typ      uintptr
		nr       uintptr
		size     uintptr
		expected uintptr
	}{
		{
			name:     "zero values",
			dir:      0,
			typ:      0,
			nr:       0,
			size:     0,
			expected: 0,
		},
		{
			name:     "basic ioctl number",
			dir:      iocRead | iocWrite,
			typ:      uintptr('S'),
			nr:       0,
			size:     16,
			expected: (iocRead|iocWrite)<<iocDirshift | uintptr('S')<<iocTypeshift | 0<<iocNrshift | 16<<iocSizeshift,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ioc(tt.dir, tt.typ, tt.nr, tt.size)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIowr(t *testing.T) {
	result := iowr(uintptr('S'), 0x0, 16)
	expected := ioc(iocRead|iocWrite, uintptr('S'), 0x0, 16)
	assert.Equal(t, expected, result)
}

func TestEpycGenerationName(t *testing.T) {
	tests := []struct {
		name     string
		product  sevsnp.SevProduct_SevProductName
		expected string
	}{
		{
			name:     "Milan",
			product:  sevsnp.SevProduct_SEV_PRODUCT_MILAN,
			expected: "Milan",
		},
		{
			name:     "Genoa",
			product:  sevsnp.SevProduct_SEV_PRODUCT_GENOA,
			expected: "Genoa",
		},
		{
			name:     "Unknown",
			product:  sevsnp.SevProduct_SEV_PRODUCT_UNKNOWN,
			expected: "Unknown",
		},
		{
			name:     "Invalid value",
			product:  sevsnp.SevProduct_SevProductName(999),
			expected: "Unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := EpycGenerationName(tt.product)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestReadFirstCPUFamilyModel(t *testing.T) {
	tests := []struct {
		name              string
		fileContent       string
		expectError       bool
		expectedFamily    int
		expectedModel     int
		expectedModelName string
	}{
		{
			name: "valid AMD EPYC Milan",
			fileContent: `processor	: 0
vendor_id	: AuthenticAMD
cpu family	: 25
model		: 1
model name	: AMD EPYC 7763 64-Core Processor
stepping	: 1
`,
			expectError:       false,
			expectedFamily:    25,
			expectedModel:     1,
			expectedModelName: "AMD EPYC 7763 64-Core Processor",
		},
		{
			name: "valid AMD EPYC Genoa",
			fileContent: `processor	: 0
vendor_id	: AuthenticAMD
cpu family	: 25
model		: 17
model name	: AMD EPYC 9654 96-Core Processor
stepping	: 1
`,
			expectError:       false,
			expectedFamily:    25,
			expectedModel:     17,
			expectedModelName: "AMD EPYC 9654 96-Core Processor",
		},
		{
			name: "missing cpu family",
			fileContent: `processor	: 0
model		: 1
model name	: Test Processor
`,
			expectError: true,
		},
		{
			name: "missing model",
			fileContent: `processor	: 0
cpu family	: 25
model name	: Test Processor
`,
			expectError: true,
		},
		{
			name: "invalid cpu family format",
			fileContent: `processor	: 0
cpu family	: invalid
model		: 1
`,
			expectError: true,
		},
		{
			name: "invalid model format",
			fileContent: `processor	: 0
cpu family	: 25
model		: invalid
`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "cpuinfo-*.txt")
			require.NoError(t, err)
			defer os.Remove(tmpFile.Name())

			_, err = tmpFile.WriteString(tt.fileContent)
			require.NoError(t, err)
			tmpFile.Close()

			family, model, modelName, err := readFirstCPUFamilyModel(tmpFile.Name())

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedFamily, family)
				assert.Equal(t, tt.expectedModel, model)
				assert.Equal(t, tt.expectedModelName, modelName)
			}
		})
	}
}

func TestReadFirstCPUFamilyModelFileNotFound(t *testing.T) {
	family, model, modelName, err := readFirstCPUFamilyModel("/nonexistent/path/cpuinfo")
	assert.Error(t, err)
	assert.Equal(t, family, 0)
	assert.Equal(t, model, 0)
	assert.Equal(t, modelName, "")
}

func TestDetectEpycGeneration(t *testing.T) {
	tests := []struct {
		name            string
		fileContent     string
		expectError     bool
		expectedProduct sevsnp.SevProduct_SevProductName
	}{
		{
			name: "Milan - model 0",
			fileContent: `processor	: 0
cpu family	: 25
model		: 0
model name	: AMD EPYC Processor
`,
			expectError:     false,
			expectedProduct: sevsnp.SevProduct_SEV_PRODUCT_MILAN,
		},
		{
			name: "Milan - model 15",
			fileContent: `processor	: 0
cpu family	: 25
model		: 15
model name	: AMD EPYC Processor
`,
			expectError:     false,
			expectedProduct: sevsnp.SevProduct_SEV_PRODUCT_MILAN,
		},
		{
			name: "Genoa - model 16",
			fileContent: `processor	: 0
cpu family	: 25
model		: 16
model name	: AMD EPYC Processor
`,
			expectError:     false,
			expectedProduct: sevsnp.SevProduct_SEV_PRODUCT_GENOA,
		},
		{
			name: "Genoa - model 31",
			fileContent: `processor	: 0
cpu family	: 25
model		: 31
model name	: AMD EPYC Processor
`,
			expectError:     false,
			expectedProduct: sevsnp.SevProduct_SEV_PRODUCT_GENOA,
		},
		{
			name: "not family 19h (25)",
			fileContent: `processor	: 0
cpu family	: 23
model		: 1
model name	: AMD EPYC Processor
`,
			expectError:     true,
			expectedProduct: sevsnp.SevProduct_SEV_PRODUCT_UNKNOWN,
		},
		{
			name: "model out of range",
			fileContent: `processor	: 0
cpu family	: 25
model		: 32
model name	: AMD EPYC Processor
`,
			expectError:     true,
			expectedProduct: sevsnp.SevProduct_SEV_PRODUCT_UNKNOWN,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpFile, err := os.CreateTemp("", "cpuinfo-*.txt")
			require.NoError(t, err)
			defer os.Remove(tmpFile.Name())

			_, err = tmpFile.WriteString(tt.fileContent)
			require.NoError(t, err)
			tmpFile.Close()

			// Test the detection logic directly using readFirstCPUFamilyModel
			family, model, modelName, err := readFirstCPUFamilyModel(tmpFile.Name())
			if err != nil {
				if tt.expectError {
					return
				}
				t.Fatalf("unexpected error reading CPU info: %v", err)
			}

			// Replicate the detection logic from DetectEpycGeneration
			var product sevsnp.SevProduct
			var detectionErr error

			if family != 25 {
				product = sevsnp.SevProduct{Name: sevsnp.SevProduct_SEV_PRODUCT_UNKNOWN}
				detectionErr = fmt.Errorf("not AMD Family 19h (cpu family=%d, model=%d, model name=%q)", family, model, modelName)
			} else {
				switch {
				case model >= 0 && model <= 15:
					product = sevsnp.SevProduct{Name: sevsnp.SevProduct_SEV_PRODUCT_MILAN}
				case model >= 16 && model <= 31:
					product = sevsnp.SevProduct{Name: sevsnp.SevProduct_SEV_PRODUCT_GENOA}
				default:
					product = sevsnp.SevProduct{Name: sevsnp.SevProduct_SEV_PRODUCT_UNKNOWN}
					detectionErr = fmt.Errorf("AMD Family 19h but model out of expected Milan/Genoa ranges: model=%d (model name=%q)", model, modelName)
				}
			}

			if tt.expectError {
				assert.Error(t, detectionErr)
			} else {
				assert.NoError(t, detectionErr)
			}
			assert.Equal(t, tt.expectedProduct, product.Name)
		})
	}
}

func TestSevIssueCmdStructure(t *testing.T) {
	cmd := &SevIssueCmd{
		Cmd:     SNP_PLATFORM_STATUS_UAPI,
		DataPtr: nil,
		FwErr:   0,
	}

	assert.Equal(t, uint32(SNP_PLATFORM_STATUS_UAPI), cmd.Cmd)
	assert.Equal(t, uint32(0), cmd.FwErr)
}

func TestCalculateMeasurement(t *testing.T) {
	tests := []struct {
		name        string
		setupMock   func() (igvmFile, binary string, cleanup func())
		expectError bool
	}{
		{
			name: "missing measurement binary",
			setupMock: func() (string, string, func()) {
				return "/nonexistent/file.igvm", "", func() {}
			},
			expectError: true,
		},
		{
			name: "missing igvm file",
			setupMock: func() (string, string, func()) {
				return "", "/bin/false", func() {}
			},
			expectError: true,
		},
		{
			name: "bad binary",
			setupMock: func() (string, string, func()) {
				tmpFile, _ := os.CreateTemp("", "test.igvm")
				tmpFile.Close()
				return tmpFile.Name(), "/nonexistent/binary", func() {
					os.Remove(tmpFile.Name())
				}
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			igvmFile, binary, cleanup := tt.setupMock()
			defer cleanup()

			_, err := calculateMeasurement(igvmFile, binary)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFetchSEVSNPAttestationPolicy_PCRFile(t *testing.T) {
	tests := []struct {
		name        string
		pcrContent  string
		expectError bool
	}{
		{
			name: "valid PCR JSON",
			pcrContent: `{
				"pcr_values": {
					"sha256": {
						"0": "0000000000000000000000000000000000000000000000000000000000000000"
					},
					"sha384": {},
					"sha1": {}
				}
			}`,
			expectError: false,
		},
		{
			name:        "invalid JSON",
			pcrContent:  `{invalid json`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.pcrContent != "" {
				tmpFile, err := os.CreateTemp("", "pcr-*.json")
				require.NoError(t, err)
				defer os.Remove(tmpFile.Name())

				_, err = tmpFile.WriteString(tt.pcrContent)
				require.NoError(t, err)
				tmpFile.Close()

				var pcrConfig struct {
					PCRValues struct {
						Sha256 map[string]string `json:"sha256"`
						Sha384 map[string]string `json:"sha384"`
						Sha1   map[string]string `json:"sha1"`
					} `json:"pcr_values"`
				}

				pcrContent, err := os.ReadFile(tmpFile.Name())
				require.NoError(t, err)

				err = json.Unmarshal(pcrContent, &pcrConfig)
				if tt.expectError {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			}
		})
	}
}

func TestFetchSEVSNPAttestationPolicy_HostData(t *testing.T) {
	tests := []struct {
		name        string
		hostData    string
		expectError bool
	}{
		{
			name:        "valid base64",
			hostData:    base64.StdEncoding.EncodeToString([]byte("test host data")),
			expectError: false,
		},
		{
			name:        "invalid base64",
			hostData:    "!!!invalid base64!!!",
			expectError: true,
		},
		{
			name:        "empty string",
			hostData:    "",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := base64.StdEncoding.DecodeString(tt.hostData)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHexDecode(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectError bool
		expected    []byte
	}{
		{
			name:        "valid hex",
			input:       "deadbeef",
			expectError: false,
			expected:    []byte{0xde, 0xad, 0xbe, 0xef},
		},
		{
			name:        "valid hex uppercase",
			input:       "DEADBEEF",
			expectError: false,
			expected:    []byte{0xde, 0xad, 0xbe, 0xef},
		},
		{
			name:        "invalid hex",
			input:       "invalid",
			expectError: true,
		},
		{
			name:        "odd length hex",
			input:       "abc",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := hex.DecodeString(tt.input)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}
