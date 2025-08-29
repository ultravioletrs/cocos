// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	tpmAttest "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/proto/tpm"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/pkg/attestation/mocks"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

func TestAddSEVSNPVerificationOptions(t *testing.T) {
	cmd := &cobra.Command{
		Use: "test",
	}

	result := addSEVSNPVerificationOptions(cmd)

	assert.Equal(t, cmd, result)

	// Check that important flags are added
	flags := []string{
		"host_data",
		"family_id",
		"image_id",
		"report_id",
		"report_id_ma",
		"measurement",
		"chip_id",
		"minimum_tcb",
		"minimum_lauch_tcb",
		"guest_policy",
		"minimum_guest_svn",
		"minimum_build",
		"check_crl",
		"timeout",
		"max_retry_delay",
		"require_author_key",
		"require_id_block",
		"platform_info",
		"minimum_version",
		"trusted_author_keys",
		"trusted_author_key_hashes",
		"trusted_id_keys",
		"trusted_id_key_hashes",
		"product",
		"stepping",
		"CA_bundles_paths",
		"CA_bundles",
	}

	for _, flagName := range flags {
		flag := cmd.Flags().Lookup(flagName)
		assert.NotNil(t, flag, "Flag %s should exist", flagName)
	}
}

func TestValidateInput(t *testing.T) {
	tests := []struct {
		name      string
		setupCfg  func()
		expectErr bool
		errMsg    string
	}{
		{
			name: "valid empty config",
			setupCfg: func() {
				cfg = check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}}
			},
			expectErr: false,
		},
		{
			name: "CA bundles without product name",
			setupCfg: func() {
				cfg = check.Config{
					Policy: &check.Policy{},
					RootOfTrust: &check.RootOfTrust{
						CabundlePaths: []string{"test.pem"},
						ProductLine:   "",
					},
				}
			},
			expectErr: true,
			errMsg:    "product name must be set if CA bundles are provided",
		},
		{
			name: "invalid report_data length",
			setupCfg: func() {
				cfg = check.Config{
					Policy: &check.Policy{
						ReportData: []byte("invalid"),
					},
					RootOfTrust: &check.RootOfTrust{},
				}
			},
			expectErr: true,
			errMsg:    "report_data",
		},
		{
			name: "invalid host_data length",
			setupCfg: func() {
				cfg = check.Config{
					Policy: &check.Policy{
						HostData: []byte("invalid"),
					},
					RootOfTrust: &check.RootOfTrust{},
				}
			},
			expectErr: true,
			errMsg:    "host_data",
		},
		{
			name: "invalid family_id length",
			setupCfg: func() {
				cfg = check.Config{
					Policy: &check.Policy{
						FamilyId: []byte("invalid"),
					},
					RootOfTrust: &check.RootOfTrust{},
				}
			},
			expectErr: true,
			errMsg:    "family_id",
		},
		{
			name: "invalid image_id length",
			setupCfg: func() {
				cfg = check.Config{
					Policy: &check.Policy{
						ImageId: []byte("invalid"),
					},
					RootOfTrust: &check.RootOfTrust{},
				}
			},
			expectErr: true,
			errMsg:    "image_id",
		},
		{
			name: "invalid trusted author key hash",
			setupCfg: func() {
				cfg = check.Config{
					Policy: &check.Policy{
						TrustedAuthorKeyHashes: [][]byte{[]byte("invalid")},
					},
					RootOfTrust: &check.RootOfTrust{},
				}
			},
			expectErr: true,
			errMsg:    "trusted_author_key_hash",
		},
		{
			name: "invalid trusted id key hash",
			setupCfg: func() {
				cfg = check.Config{
					Policy: &check.Policy{
						TrustedIdKeyHashes: [][]byte{[]byte("invalid")},
					},
					RootOfTrust: &check.RootOfTrust{},
				}
			},
			expectErr: true,
			errMsg:    "trusted_id_key_hash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupCfg()
			err := validateInput()
			if tt.expectErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParseTrustedKeys(t *testing.T) {
	tempDir := t.TempDir()

	authorKeyFile := filepath.Join(tempDir, "author.pem")
	idKeyFile := filepath.Join(tempDir, "id.pem")
	nonExistentFile := filepath.Join(tempDir, "nonexistent.pem")

	authorKeyContent := "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAOI..."
	idKeyContent := "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAOI..."

	require.NoError(t, os.WriteFile(authorKeyFile, []byte(authorKeyContent), 0o644))
	require.NoError(t, os.WriteFile(idKeyFile, []byte(idKeyContent), 0o644))

	tests := []struct {
		name              string
		trustedAuthorKeys []string
		trustedIdKeys     []string
		expectErr         bool
	}{
		{
			name:              "valid files",
			trustedAuthorKeys: []string{authorKeyFile},
			trustedIdKeys:     []string{idKeyFile},
			expectErr:         false,
		},
		{
			name:              "nonexistent author key file",
			trustedAuthorKeys: []string{nonExistentFile},
			trustedIdKeys:     []string{},
			expectErr:         true,
		},
		{
			name:              "nonexistent id key file",
			trustedAuthorKeys: []string{},
			trustedIdKeys:     []string{nonExistentFile},
			expectErr:         true,
		},
		{
			name:              "empty file lists",
			trustedAuthorKeys: []string{},
			trustedIdKeys:     []string{},
			expectErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg = check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}}
			trustedAuthorKeys = tt.trustedAuthorKeys
			trustedIdKeys = tt.trustedIdKeys

			err := parseTrustedKeys()
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if len(tt.trustedAuthorKeys) > 0 {
					assert.Len(t, cfg.Policy.TrustedAuthorKeys, len(tt.trustedAuthorKeys))
					assert.Equal(t, []byte(authorKeyContent), cfg.Policy.TrustedAuthorKeys[0])
				}
				if len(tt.trustedIdKeys) > 0 {
					assert.Len(t, cfg.Policy.TrustedIdKeys, len(tt.trustedIdKeys))
					assert.Equal(t, []byte(idKeyContent), cfg.Policy.TrustedIdKeys[0])
				}
			}
		})
	}
}

func TestParseUints(t *testing.T) {
	tests := []struct {
		name             string
		stepping         string
		platformInfo     string
		expectErr        bool
		expectedStep     *uint32
		expectedPlatform *uint64
	}{
		{
			name:         "empty values",
			stepping:     "",
			platformInfo: "",
			expectErr:    false,
		},
		{
			name:             "decimal values",
			stepping:         "5",
			platformInfo:     "10",
			expectErr:        false,
			expectedStep:     uint32Ptr(5),
			expectedPlatform: uint64Ptr(10),
		},
		{
			name:             "hex values",
			stepping:         "0x5",
			platformInfo:     "0xa",
			expectErr:        false,
			expectedStep:     uint32Ptr(5),
			expectedPlatform: uint64Ptr(10),
		},
		{
			name:             "octal values",
			stepping:         "0o7",
			platformInfo:     "0o12",
			expectErr:        false,
			expectedStep:     uint32Ptr(7),
			expectedPlatform: uint64Ptr(10),
		},
		{
			name:             "binary values",
			stepping:         "0b101",
			platformInfo:     "0b1010",
			expectErr:        false,
			expectedStep:     uint32Ptr(5),
			expectedPlatform: uint64Ptr(10),
		},
		{
			name:         "invalid stepping",
			stepping:     "invalid",
			platformInfo: "",
			expectErr:    true,
		},
		{
			name:         "invalid platform info",
			stepping:     "",
			platformInfo: "invalid",
			expectErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg = check.Config{Policy: &check.Policy{Product: &sevsnp.SevProduct{}}, RootOfTrust: &check.RootOfTrust{}}
			stepping = tt.stepping
			platformInfo = tt.platformInfo

			err := parseUints()
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.expectedStep != nil {
					assert.Equal(t, *tt.expectedStep, cfg.Policy.Product.MachineStepping.Value)
				}
				if tt.expectedPlatform != nil {
					assert.Equal(t, *tt.expectedPlatform, cfg.Policy.PlatformInfo.Value)
				}
			}
		})
	}
}

func TestGetBase(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"0x10", 16},
		{"0o10", 8},
		{"0b10", 2},
		{"10", 10},
		{"", 10},
		{"abc", 10},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := getBase(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseConfig(t *testing.T) {
	tempDir := t.TempDir()

	validConfig := map[string]any{
		"rootOfTrust": map[string]any{
			"product":         "test_product",
			"cabundlePaths":   []string{"test_path"},
			"cabundles":       []string{"test_bundle"},
			"checkCrl":        true,
			"disallowNetwork": true,
		},
		"policy": map[string]any{
			"minimumGuestSvn":  1,
			"policy":           "1",
			"minimumBuild":     1,
			"minimumVersion":   "0.90",
			"requireAuthorKey": true,
			"requireIdBlock":   true,
		},
	}

	tests := []struct {
		name        string
		setupConfig func() string
		expectErr   bool
	}{
		{
			name: "empty config string",
			setupConfig: func() string {
				return ""
			},
			expectErr: false,
		},
		{
			name: "valid config file",
			setupConfig: func() string {
				configFile := filepath.Join(tempDir, "valid_config.json")
				configBytes, err := json.Marshal(validConfig)
				assert.NoError(t, err)
				if err := os.WriteFile(configFile, configBytes, 0o644); err != nil {
					t.Errorf("failed to write config file: %v", err)
				}
				return configFile
			},
			expectErr: false,
		},
		{
			name: "nonexistent config file",
			setupConfig: func() string {
				return filepath.Join(tempDir, "nonexistent.json")
			},
			expectErr: true,
		},
		{
			name: "invalid JSON config",
			setupConfig: func() string {
				configFile := filepath.Join(tempDir, "invalid_config.json")
				if err := os.WriteFile(configFile, []byte("invalid json"), 0o644); err != nil {
					t.Errorf("failed to write invalid config file: %v", err)
				}
				return configFile
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg = check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}}
			cfgString = tt.setupConfig()

			err := parseConfig()
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cfg.Policy)
				assert.NotNil(t, cfg.RootOfTrust)
			}
		})
	}
}

func TestParseHashes(t *testing.T) {
	tests := []struct {
		name                string
		trustedAuthorHashes []string
		trustedIdKeyHashes  []string
		expectErr           bool
	}{
		{
			name:                "valid hashes",
			trustedAuthorHashes: []string{"deadbeef", "cafebabe"},
			trustedIdKeyHashes:  []string{"12345678", "87654321"},
			expectErr:           false,
		},
		{
			name:                "empty hashes",
			trustedAuthorHashes: []string{},
			trustedIdKeyHashes:  []string{},
			expectErr:           false,
		},
		{
			name:                "invalid author hash",
			trustedAuthorHashes: []string{"invalid_hex"},
			trustedIdKeyHashes:  []string{},
			expectErr:           true,
		},
		{
			name:                "invalid id key hash",
			trustedAuthorHashes: []string{},
			trustedIdKeyHashes:  []string{"invalid_hex"},
			expectErr:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg = check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}}
			trustedAuthorHashes = tt.trustedAuthorHashes
			trustedIdKeyHashes = tt.trustedIdKeyHashes

			err := parseHashes()
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, cfg.Policy.TrustedAuthorKeyHashes, len(tt.trustedAuthorHashes))
				assert.Len(t, cfg.Policy.TrustedIdKeyHashes, len(tt.trustedIdKeyHashes))

				for i, hash := range tt.trustedAuthorHashes {
					expected, _ := hex.DecodeString(hash)
					assert.Equal(t, expected, cfg.Policy.TrustedAuthorKeyHashes[i])
				}

				for i, hash := range tt.trustedIdKeyHashes {
					expected, _ := hex.DecodeString(hash)
					assert.Equal(t, expected, cfg.Policy.TrustedIdKeyHashes[i])
				}
			}
		})
	}
}

func TestParseAttestationFile(t *testing.T) {
	tempDir := t.TempDir()

	binaryFile := filepath.Join(tempDir, "attestation.bin")
	jsonFile := filepath.Join(tempDir, "attestation.json")

	binaryData := make([]byte, 1024)
	for i := range binaryData {
		binaryData[i] = byte(i % 256)
	}

	jsonData := &sevsnp.Attestation{
		Report: &sevsnp.Report{
			FamilyId:        make([]byte, 16),
			ImageId:         make([]byte, 16),
			ReportData:      make([]byte, 64),
			Measurement:     make([]byte, 48),
			HostData:        make([]byte, 32),
			IdKeyDigest:     make([]byte, 48),
			AuthorKeyDigest: make([]byte, 48),
			ReportId:        make([]byte, 32),
			ReportIdMa:      make([]byte, 32),
			ChipId:          make([]byte, 64),
			Signature:       make([]byte, 512),
		},
	}
	jsonBytes, err := json.Marshal(jsonData)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(binaryFile, binaryData, 0o644))
	require.NoError(t, os.WriteFile(jsonFile, jsonBytes, 0o644))

	tests := []struct {
		name            string
		attestationFile string
		expectErr       bool
	}{
		{
			name:            "valid binary file",
			attestationFile: binaryFile,
			expectErr:       false,
		},
		{
			name:            "valid JSON file",
			attestationFile: jsonFile,
			expectErr:       false,
		},
		{
			name:            "nonexistent file",
			attestationFile: filepath.Join(tempDir, "nonexistent.bin"),
			expectErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestationFile = tt.attestationFile

			err := parseAttestationFile()
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, attestationRaw)
				assert.NotEmpty(t, attestationRaw)
			}
		})
	}
}

func TestSevsnpverify(t *testing.T) {
	trustedAuthorHashes = []string{}
	trustedIdKeyHashes = []string{}
	stepping = ""
	platformInfo = ""
	tempDir := t.TempDir()
	cfg = check.Config{Policy: &check.Policy{Product: &sevsnp.SevProduct{}}, RootOfTrust: &check.RootOfTrust{}}

	attestationFile := filepath.Join(tempDir, "attestation.bin")
	attestationData := make([]byte, abi.ReportSize+100)
	for i := range attestationData {
		attestationData[i] = byte(i % 256)
	}
	require.NoError(t, os.WriteFile(attestationFile, attestationData, 0o644))

	tests := []struct {
		name        string
		args        []string
		setupMock   func(*mocks.Verifier)
		expectErr   bool
		expectedMsg string
	}{
		{
			name: "successful verification",
			args: []string{attestationFile},
			setupMock: func(m *mocks.Verifier) {
				m.On("VerifTeeAttestation", mock.Anything, mock.Anything).Return(nil)
			},
			expectErr:   false,
			expectedMsg: "Attestation validation and verification is successful!",
		},
		{
			name: "verification failure",
			args: []string{attestationFile},
			setupMock: func(m *mocks.Verifier) {
				m.On("VerifTeeAttestation", mock.Anything, mock.Anything).Return(fmt.Errorf("verification failed"))
			},
			expectErr:   true,
			expectedMsg: "attestation validation and verification failed",
		},
		{
			name:      "nonexistent file",
			args:      []string{filepath.Join(tempDir, "nonexistent.bin")},
			setupMock: func(m *mocks.Verifier) {},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfgString = ""

			mockVerifier := new(mocks.Verifier)
			tt.setupMock(mockVerifier)

			var output bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetOut(&output)

			err := sevsnpverify(cmd, mockVerifier, tt.args)
			fmt.Println("error1", err)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.expectedMsg != "" {
					assert.Contains(t, output.String(), tt.expectedMsg)
				}
			}

			mockVerifier.AssertExpectations(t)
		})
	}
}

func TestReturnvTPMAttestation(t *testing.T) {
	tempDir := t.TempDir()

	attestation := &tpmAttest.Attestation{
		Quotes: []*tpm.Quote{
			{
				Quote:  []byte("test quote"),
				RawSig: []byte("test signature"),
			},
		},
	}

	binaryData, err := proto.Marshal(attestation)
	require.NoError(t, err)

	binaryFile := filepath.Join(tempDir, "attestation.pb")
	require.NoError(t, os.WriteFile(binaryFile, binaryData, 0o644))

	textData, err := prototext.Marshal(attestation)
	require.NoError(t, err)

	textFile := filepath.Join(tempDir, "attestation.txtpb")
	require.NoError(t, os.WriteFile(textFile, textData, 0o644))

	tests := []struct {
		name      string
		args      []string
		format    string
		expectErr bool
	}{
		{
			name:      "binary protobuf format",
			args:      []string{binaryFile},
			format:    FormatBinaryPB,
			expectErr: false,
		},
		{
			name:      "text protobuf format",
			args:      []string{textFile},
			format:    FormatTextProto,
			expectErr: false,
		},
		{
			name:      "invalid format",
			args:      []string{binaryFile},
			format:    "invalid",
			expectErr: true,
		},
		{
			name:      "nonexistent file",
			args:      []string{filepath.Join(tempDir, "nonexistent.pb")},
			format:    FormatBinaryPB,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format = tt.format

			result, err := returnvTPMAttestation(tt.args)

			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.NotEmpty(t, result)
			}
		})
	}
}

func TestVtpmSevSnpverify(t *testing.T) {
	stepping = ""
	platformInfo = ""
	trustedAuthorHashes = []string{}
	trustedIdKeyHashes = []string{}
	cfg = check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}}
	tempDir := t.TempDir()

	attestation := &tpmAttest.Attestation{
		Quotes: []*tpm.Quote{
			{
				Quote:  []byte("test quote"),
				RawSig: []byte("test signature"),
			},
		},
	}

	binaryData, err := proto.Marshal(attestation)
	require.NoError(t, err)

	attestationFile := filepath.Join(tempDir, "vtpm_attestation.pb")
	require.NoError(t, os.WriteFile(attestationFile, binaryData, 0o644))

	tests := []struct {
		name      string
		args      []string
		setupMock func(*mocks.Verifier)
		expectErr bool
	}{
		{
			name: "successful verification",
			args: []string{attestationFile},
			setupMock: func(m *mocks.Verifier) {
				m.On("VerifyAttestation", mock.Anything, mock.Anything, mock.Anything).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "verification failure",
			args: []string{attestationFile},
			setupMock: func(m *mocks.Verifier) {
				m.On("VerifyAttestation", mock.Anything, mock.Anything, mock.Anything).Return(fmt.Errorf("verification failed"))
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg = check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}}
			cfgString = ""
			format = FormatBinaryPB

			mockVerifier := new(mocks.Verifier)
			tt.setupMock(mockVerifier)

			err := vtpmSevSnpverify(tt.args, mockVerifier)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			mockVerifier.AssertExpectations(t)
		})
	}
}

func TestVtpmverify(t *testing.T) {
	tempDir := t.TempDir()

	attestation := &tpmAttest.Attestation{
		Quotes: []*tpm.Quote{
			{
				Quote:  []byte("test quote"),
				RawSig: []byte("test signature"),
			},
		},
	}

	binaryData, err := proto.Marshal(attestation)
	require.NoError(t, err)

	attestationFile := filepath.Join(tempDir, "vtpm_attestation.pb")
	require.NoError(t, os.WriteFile(attestationFile, binaryData, 0o644))

	tests := []struct {
		name      string
		args      []string
		setupMock func(*mocks.Verifier)
		expectErr bool
	}{
		{
			name: "successful verification",
			args: []string{attestationFile},
			setupMock: func(m *mocks.Verifier) {
				m.On("VerifVTpmAttestation", mock.Anything, mock.Anything).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "verification failure",
			args: []string{attestationFile},
			setupMock: func(m *mocks.Verifier) {
				m.On("VerifVTpmAttestation", mock.Anything, mock.Anything).Return(fmt.Errorf("verification failed"))
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			format = FormatBinaryPB

			mockVerifier := new(mocks.Verifier)
			tt.setupMock(mockVerifier)

			err := vtpmverify(tt.args, mockVerifier)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			mockVerifier.AssertExpectations(t)
		})
	}
}

func uint32Ptr(v uint32) *uint32 {
	return &v
}

func uint64Ptr(v uint64) *uint64 {
	return &v
}
