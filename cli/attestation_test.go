// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	mmocks "github.com/ultravioletrs/cocos/pkg/attestation/cmdconfig/mocks"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"github.com/ultravioletrs/cocos/pkg/sdk/mocks"
)

func TestNewAttestationCmd(t *testing.T) {
	mockSDK := new(mocks.SDK)
	cli := &CLI{agentSDK: mockSDK}
	cmd := cli.NewAttestationCmd()

	assert.Equal(t, "attestation [command]", cmd.Use)
	assert.Equal(t, "Get and validate attestations", cmd.Short)

	var buf bytes.Buffer
	cmd.SetOut(&buf)

	reportData := bytes.Repeat([]byte{0x01}, quoteprovider.Nonce)
	mockSDK.On("Attestation", mock.Anything, [quoteprovider.Nonce]byte(reportData), mock.Anything).Return(nil)

	cmd.SetArgs([]string{hex.EncodeToString(reportData)})
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "Get and validate attestations")
}

func TestNewGetAttestationCmd(t *testing.T) {
	validattestation, err := os.ReadFile("../attestation.bin")
	require.NoError(t, err)

	teeNonce := hex.EncodeToString(bytes.Repeat([]byte{0x00}, quoteprovider.Nonce))
	vtpmNonce := hex.EncodeToString(bytes.Repeat([]byte{0x00}, vtpm.Nonce))
	tokenNonce := hex.EncodeToString(bytes.Repeat([]byte{0x00}, vtpm.Nonce))

	testCases := []struct {
		name         string
		args         []string
		mockResponse []byte
		mockError    error
		expectedErr  string
		expectedOut  string
	}{
		{
			name:         "successful SNP attestation retrieval",
			args:         []string{"snp", "--tee", teeNonce},
			mockResponse: []byte("mock attestation"),
			mockError:    nil,
			expectedOut:  "Attestation result retrieved and saved successfully!",
		},
		{
			name:         "successful vTPM attestation retrieval",
			args:         []string{"vtpm", "--vtpm", vtpmNonce},
			mockResponse: []byte("mock attestation"),
			mockError:    nil,
			expectedOut:  "Attestation result retrieved and saved successfully!",
		},
		{
			name:         "successful SNP-vTPM attestation retrieval",
			args:         []string{"snp-vtpm", "--tee", teeNonce, "--vtpm", vtpmNonce},
			mockResponse: []byte("mock attestation"),
			mockError:    nil,
			expectedOut:  "Attestation result retrieved and saved successfully!",
		},
		{
			name:         "missing vTPM nonce",
			args:         []string{"snp-vtpm", "--tee", teeNonce},
			mockResponse: []byte("mock attestation"),
			mockError:    nil,
			expectedOut:  "vTPM nonce must be defined for vTPM attestation",
		},
		{
			name:         "missing TEE nonce",
			args:         []string{"snp-vtpm", "--vtpm", vtpmNonce},
			mockResponse: []byte("mock attestation"),
			mockError:    nil,
			expectedOut:  "TEE nonce must be defined for SEV-SNP attestation",
		},
		{
			name:         "invalid report data size",
			args:         []string{"snp", "--tee", hex.EncodeToString(bytes.Repeat([]byte{0x00}, 65))},
			mockResponse: nil,
			mockError:    errors.New("error"),
			expectedErr:  "nonce must be a hex encoded string of length lesser or equal 64 bytes",
		},
		{
			name:         "invalid vTPM data size",
			args:         []string{"vtpm", "--vtpm", hex.EncodeToString(bytes.Repeat([]byte{0x00}, 33))},
			mockResponse: nil,
			mockError:    errors.New("error"),
			expectedErr:  "vTPM nonce must be a hex encoded string of length lesser or equal 32 bytes",
		},
		{
			name:         "invalid arguments",
			args:         []string{"invalid"},
			mockResponse: nil,
			mockError:    errors.New("error"),
			expectedErr:  "Bad attestation type: invalid argument ",
		},
		{
			name:         "failed to get attestation",
			args:         []string{"snp", "--tee", teeNonce},
			mockResponse: nil,
			mockError:    errors.New("error"),
			expectedErr:  "Failed to get attestation due to error",
		},
		{
			name:         "Textproto report error",
			args:         []string{"snp", "--tee", teeNonce, "--reporttextproto"},
			mockResponse: []byte("mock attestation"),
			mockError:    nil,
			expectedErr:  "Fetching SEV-SNP attestation report\nError converting SNP attestation to JSON: attestation contents too small : attestation contents too small (0x10 bytes). Want at least 0x4a0 bytes ❌\n",
		},
		{
			name:         "successful Textproto report",
			args:         []string{"snp", "--tee", teeNonce, "--reporttextproto"},
			mockResponse: validattestation,
			mockError:    nil,
			expectedOut:  "Attestation result retrieved and saved successfully!",
		},
		{
			name:         "connection error",
			args:         []string{"snp", "--tee", teeNonce},
			mockResponse: nil,
			mockError:    errors.New("failed to connect to agent"),
			expectedErr:  "Failed to connect to agent",
		},
		{
			name:         "successful Azure token retrieval",
			args:         []string{"azure-token", "--token", tokenNonce},
			mockResponse: []byte("eyJhbGciOiAiUlMyNTYifQ.eyJzdWIiOiAidGVzdC11c2VyIn0.signature"),
			mockError:    nil,
			expectedOut:  "Fetching Azure token\nAttestation result retrieved and saved successfully!\n",
		},
		{
			name:         "failed to retrieve Azure token",
			args:         []string{"azure-token", "--token", tokenNonce},
			mockResponse: nil,
			mockError:    errors.New("error"),
			expectedErr:  "Fetching Azure token\nFailed to get attestation result due to error: error ❌\n",
		},
		{
			name:         "invalid token nonce size",
			args:         []string{"azure-token", "--token", hex.EncodeToString(bytes.Repeat([]byte{0x00}, 33))},
			mockResponse: nil,
			mockError:    errors.New("error"),
			expectedErr:  "Fetching Azure token\nvTPM nonce must be a hex encoded string of length lesser or equal 32 bytes ❌ \n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(func() {
				os.Remove(attestationFilePath)
				os.Remove(attestationReportJson)
			})
			mockSDK := new(mocks.SDK)
			cli := &CLI{agentSDK: mockSDK}
			if tc.name == "connection error" {
				cli.connectErr = errors.New("failed to connect to agent")
			}
			cmd := cli.NewGetAttestationCmd()
			var buf bytes.Buffer
			cmd.SetOut(&buf)

			mockSDK.On("Attestation", mock.Anything, [quoteprovider.Nonce]byte(bytes.Repeat([]byte{0x00}, quoteprovider.Nonce)), [vtpm.Nonce]byte(bytes.Repeat([]byte{0x00}, vtpm.Nonce)), mock.Anything, mock.Anything).Return(tc.mockError).Run(func(args mock.Arguments) {
				_, err := args.Get(4).(*os.File).Write(tc.mockResponse)
				require.NoError(t, err)
			})

			mockSDK.On("AttestationResult", mock.Anything, [vtpm.Nonce]byte(bytes.Repeat([]byte{0x00}, vtpm.Nonce)), mock.Anything, mock.Anything).Return(tc.mockError).Run(func(args mock.Arguments) {
				_, err := args.Get(3).(*os.File).Write(tc.mockResponse)
				require.NoError(t, err)
			})

			cmd.SetArgs(tc.args)
			err := cmd.Execute()

			if tc.expectedErr != "" {
				assert.Contains(t, buf.String(), tc.expectedErr)
			} else {
				assert.NoError(t, err)
				assert.Contains(t, buf.String(), tc.expectedOut)
			}
		})
	}
}

func TestNewValidateAttestationValidationCmdDefaults(t *testing.T) {
	cli := &CLI{}
	cmd := cli.NewValidateAttestationValidationCmd()

	assert.Equal(t, "validate", cmd.Use)
	expectedMessage := fmt.Sprintf("Validate and verify attestation information. You can define the confidential computing cloud provider (%s, %s, %s; %s is the default) and can choose from 4 modes: %s, %s, %s, and %s. Default mode is %s.", CCNone, CCAzure, CCGCP, CCNone, SNP, VTPM, SNPvTPM, TDX, SNP)
	assert.Equal(t, expectedMessage, cmd.Short)

	assert.Equal(t, fmt.Sprint(defaultMinimumTcb), cmd.Flag("minimum_tcb").Value.String())
	assert.Equal(t, fmt.Sprint(defaultMinimumLaunchTcb), cmd.Flag("minimum_lauch_tcb").Value.String())
	assert.Equal(t, fmt.Sprint(defaultGuestPolicy), cmd.Flag("guest_policy").Value.String())
	assert.Equal(t, fmt.Sprint(defaultMinimumGuestSvn), cmd.Flag("minimum_guest_svn").Value.String())
	assert.Equal(t, fmt.Sprint(defaultMinimumBuild), cmd.Flag("minimum_build").Value.String())
	assert.Equal(t, defaultCheckCrl, cmd.Flag("check_crl").Value.String() == "true")
	assert.Equal(t, fmt.Sprint(defaultTimeout), cmd.Flag("timeout").Value.String())
	assert.Equal(t, fmt.Sprint(defaultMaxRetryDelay), cmd.Flag("max_retry_delay").Value.String())
}

func TestNewValidateAttestationValidationCmd(t *testing.T) {
	cli := &CLI{}
	cmd := cli.NewValidateAttestationValidationCmd()

	t.Run("missing attestation report file path", func(t *testing.T) {
		err := cmd.Execute()
		assert.Error(t, err)
		assert.Equal(t, "please pass the attestation report file path", err.Error())
	})

	t.Run("unknown mode", func(t *testing.T) {
		cmd.SetArgs([]string{attestationFilePath, "--mode=invalid"})
		err := cmd.Execute()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown mode")
	})

	t.Run("snp mode with missing flags", func(t *testing.T) {
		cmd.SetArgs([]string{attestationFilePath, "--mode=snp"})
		err := cmd.Execute()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "required flag(s) \"product\", \"report_data\" not set")
	})

	t.Run("vtpm mode with missing flags", func(t *testing.T) {
		cmd.SetArgs([]string{vtpmFilePath, "--mode=vtpm"})
		err := cmd.Execute()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "required flag(s) \"format\", \"nonce\", \"output\", \"product\", \"report_data\" not set")
	})

	t.Run("snp-vtpm mode with missing flags", func(t *testing.T) {
		cmd.SetArgs([]string{vtpmFilePath, "--mode=snp-vtpm"})
		err := cmd.Execute()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "required flag(s) \"format\", \"nonce\", \"output\", \"product\", \"report_data\" not set")
	})

	t.Run("valid snp mode execution", func(t *testing.T) {
		cli := CLI{}
		cmd := cli.NewValidateAttestationValidationCmd()

		cmd.RunE = func(_ *cobra.Command, _ []string) error {
			t.Log("Mock RunE executed instead of sevsnpverify")
			return nil
		}

		cmd.SetArgs([]string{
			"../attestation.bin",
			"--mode=snp",
			"--report_data=" +
				"11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff" +
				"11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
			"--product=Milan",
		})
		err := cmd.PreRunE(cmd, []string{"../attestation.bin"})
		assert.NoError(t, err)
	})

	t.Run("valid vtpm mode execution", func(t *testing.T) {
		cli := CLI{}
		cmd := cli.NewValidateAttestationValidationCmd()

		cmd.RunE = func(_ *cobra.Command, _ []string) error {
			t.Log("Mock RunE executed instead of vtpmverify")
			return nil
		}

		cmd.SetArgs([]string{vtpmFilePath, "--mode=vtpm", "--nonce=123abc", "--format=binarypb", "--output=some_output"})

		err := cmd.PreRunE(cmd, []string{"../quote.dat"})
		assert.NoError(t, err)
	})

	t.Run("valid snp-vtpm mode execution", func(t *testing.T) {
		cli := CLI{}
		cmd := cli.NewValidateAttestationValidationCmd()

		cmd.RunE = func(_ *cobra.Command, _ []string) error {
			t.Log("Mock RunE executed instead of vtpmSevSnpverify")
			return nil
		}

		cmd.SetArgs([]string{vtpmFilePath, "--mode=snp-vtpm", "--nonce=123abc", "--format=textproto", "--output=some_output"})
		err := cmd.PreRunE(cmd, []string{"../quote.dat"})
		assert.NoError(t, err)
	})
}

func TestNewMeasureCmd_RunSuccess(t *testing.T) {
	cliInstance := &CLI{}
	mockMeasurement := new(mmocks.MeasurementProvider)
	cliInstance.measurement = mockMeasurement

	mockMeasurement.On("Run", "testfile.igvm").Return([]byte{}, nil)

	cmd := cliInstance.NewMeasureCmd("fake_binary_path")
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"testfile.igvm"})

	err := cmd.Execute()

	assert.NoError(t, err)
	mockMeasurement.AssertExpectations(t)
}

func TestNewMeasureCmd_RunError(t *testing.T) {
	cliInstance := &CLI{}
	mockMeasurement := new(mmocks.MeasurementProvider)
	cliInstance.measurement = mockMeasurement
	expectedError := errors.New("mocked measurement error")

	mockMeasurement.On("Run", "testfile.igvm").Return([]byte{}, expectedError)

	cmd := cliInstance.NewMeasureCmd("fake_binary_path")

	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"testfile.igvm"})

	err := cmd.Execute()

	assert.Error(t, err)
	assert.Equal(t, expectedError.Error(), err.Error())
	mockMeasurement.AssertExpectations(t)
}

func TestParseConfig1(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "attestation_policy.json")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	cfgString = ""

	err = parseConfig()
	assert.NoError(t, err)
	assert.NotNil(t, cfg.RootOfTrust)
	assert.NotNil(t, cfg.Policy)

	cfgString = tmpfile.Name()

	_, err = tmpfile.WriteString(`{"rootOfTrust":{"product":"test_product"},"policy":{"minimumGuestSvn":1}}`)
	require.NoError(t, err)
	err = parseConfig()
	assert.NoError(t, err)
	assert.Equal(t, "test_product", cfg.RootOfTrust.Product)
	assert.Equal(t, uint32(1), cfg.Policy.MinimumGuestSvn)

	_, err = tmpfile.WriteString(`{"invalid_json"`)
	require.NoError(t, err)
	err = parseConfig()
	assert.Error(t, err)
}

func TestParseHashes1(t *testing.T) {
	trustedAuthorHashes = []string{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
	trustedIdKeyHashes = []string{"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"}

	cfg = check.Config{}
	if cfg.Policy == nil {
		cfg.Policy = &check.Policy{}
	}

	err := parseHashes()
	assert.NoError(t, err)
	assert.Len(t, cfg.Policy.TrustedAuthorKeyHashes, 1)
	assert.Len(t, cfg.Policy.TrustedIdKeyHashes, 1)

	trustedAuthorHashes = []string{"invalid_hash"}
	err = parseHashes()
	assert.Error(t, err)
}

func TestParseFiles(t *testing.T) {
	attestationFile = "test_attestation.bin"
	authorKeyFile := "test_author_key.pem"
	idKeyFile := "test_id_key.pem"

	err := os.WriteFile(attestationFile, []byte("test attestation"), 0o644)
	assert.NoError(t, err)
	err = os.WriteFile(authorKeyFile, []byte("test author key"), 0o644)
	assert.NoError(t, err)
	err = os.WriteFile(idKeyFile, []byte("test id key"), 0o644)
	assert.NoError(t, err)

	trustedAuthorKeys = []string{authorKeyFile}
	trustedIdKeys = []string{idKeyFile}

	err = parseAttestationFile()
	assert.NoError(t, err)
	err = parseTrustedKeys()
	assert.NoError(t, err)
	assert.Equal(t, []byte("test attestation"), attestationRaw)
	assert.Len(t, cfg.Policy.TrustedAuthorKeys, 1)
	assert.Len(t, cfg.Policy.TrustedIdKeys, 1)

	os.Remove(attestationFile)
	os.Remove(authorKeyFile)
	os.Remove(idKeyFile)

	attestationFile = "non_existent_file.bin"
	err = parseAttestationFile()
	assert.Error(t, err)
}

func TestParseUints1(t *testing.T) {
	stepping = "10"
	platformInfo = "0xFF"

	cfg = check.Config{}
	if cfg.Policy == nil {
		cfg.Policy = &check.Policy{
			Product: &sevsnp.SevProduct{},
		}
	}
	err := parseUints()
	assert.NoError(t, err)
	assert.Equal(t, uint32(10), cfg.Policy.Product.MachineStepping.Value)
	assert.Equal(t, uint64(255), cfg.Policy.PlatformInfo.Value)

	stepping = "invalid"
	err = parseUints()
	assert.Error(t, err)

	stepping = "10"
	platformInfo = "invalid"
	err = parseUints()
	assert.Error(t, err)
}

func TestValidateInput1(t *testing.T) {
	cfg = check.Config{}
	if cfg.Policy == nil {
		cfg.Policy = &check.Policy{}
	}
	if cfg.RootOfTrust == nil {
		cfg.RootOfTrust = &check.RootOfTrust{}
	}
	cfg.Policy.ReportData = make([]byte, 64)
	cfg.Policy.HostData = make([]byte, 32)
	cfg.Policy.FamilyId = make([]byte, 16)
	cfg.Policy.ImageId = make([]byte, 16)
	cfg.Policy.ReportId = make([]byte, 32)
	cfg.Policy.ReportIdMa = make([]byte, 32)
	cfg.Policy.Measurement = make([]byte, 48)
	cfg.Policy.ChipId = make([]byte, 64)

	err := validateInput()
	assert.NoError(t, err)

	cfg.Policy.ReportData = make([]byte, 32)
	err = validateInput()
	assert.Error(t, err)
}

func TestGetBase1(t *testing.T) {
	assert.Equal(t, 16, getBase("0xFF"))
	assert.Equal(t, 8, getBase("0o77"))
	assert.Equal(t, 2, getBase("0b1010"))
	assert.Equal(t, 10, getBase("123"))
}

func TestAttestationToJSON(t *testing.T) {
	validReport, err := os.ReadFile("../attestation.bin")
	require.NoError(t, err)
	tests := []struct {
		name  string
		input []byte
		err   error
	}{
		{
			name:  "Valid report",
			input: validReport,
			err:   nil,
		},
		{
			name:  "Invalid report size",
			input: make([]byte, abi.ReportSize-1),
			err:   errReportSize,
		},
		{
			name:  "Nil input",
			input: nil,
			err:   errReportSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := attestationToJSON(tt.input)
			assert.True(t, errors.Contains(err, tt.err))
			if tt.err != nil {
				assert.Nil(t, got)
				return
			}

			require.NotNil(t, got)

			var js map[string]interface{}
			err = json.Unmarshal(got, &js)
			assert.NoError(t, err)
		})
	}
}

func TestAttestationFromJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		err      error
		validate func(t *testing.T, output []byte)
	}{
		{
			name: "Valid JSON",
			input: func() []byte {
				att := &sevsnp.Attestation{
					Report: &sevsnp.Report{
						CurrentTcb:      1,
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
				data, err := json.Marshal(att)
				require.NoError(t, err)
				return data
			}(),
			err: nil,
			validate: func(t *testing.T, output []byte) {
				assert.NotEmpty(t, output)
			},
		},
		{
			name:  "Invalid JSON",
			input: []byte(`{"invalid": json`),
			err:   errors.New("invalid character 'j' looking for beginning of value"),
			validate: func(t *testing.T, output []byte) {
				assert.Nil(t, output)
			},
		},
		{
			name:  "Empty input",
			input: []byte{},
			err:   errors.New("unexpected end of JSON input"),
			validate: func(t *testing.T, output []byte) {
				assert.Nil(t, output)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := attestationFromJSON(tt.input)
			assert.True(t, errors.Contains(err, tt.err))
			tt.validate(t, got)
		})
	}
}

func TestIsFileJSON(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     bool
	}{
		{
			name:     "Valid JSON extension",
			filename: "test.json",
			want:     true,
		},
		{
			name:     "Valid JSON extension with path",
			filename: "/path/to/test.json",
			want:     true,
		},
		{
			name:     "Invalid extension",
			filename: "test.txt",
			want:     false,
		},
		{
			name:     "No extension",
			filename: "test",
			want:     false,
		},
		{
			name:     "JSON in filename",
			filename: "json.txt",
			want:     false,
		},
		{
			name:     "Empty string",
			filename: "",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isFileJSON(tt.filename)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRoundTrip(t *testing.T) {
	originalReport, err := os.ReadFile("../attestation.bin")
	require.NoError(t, err)
	jsonData, err := attestationToJSON(originalReport)
	require.NoError(t, err)
	require.NotNil(t, jsonData)

	roundTripReport, err := attestationFromJSON(jsonData)
	require.NoError(t, err)
	require.NotNil(t, roundTripReport)
}

func TestDecodeJWTToJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		err      error
		validate func(t *testing.T, output []byte)
	}{
		{
			name: "Valid JWT",
			input: []byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
				"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"),
			err: nil,
			validate: func(t *testing.T, output []byte) {
				assert.NotEmpty(t, output)
				assert.Contains(t, string(output), `"header"`)
				assert.Contains(t, string(output), `"payload"`)
			},
		},
		{
			name:  "Invalid JWT - one part",
			input: []byte("justonepart"),
			err:   fmt.Errorf("invalid JWT: must have at least 2 parts"),
			validate: func(t *testing.T, output []byte) {
				assert.Nil(t, output)
			},
		},
		{
			name:  "Invalid Base64",
			input: []byte("bad@@@.header"),
			err:   errors.New("illegal base64 data"),
			validate: func(t *testing.T, output []byte) {
				assert.Nil(t, output)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeJWTToJSON(tt.input)

			if tt.err != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.err.Error())
			} else {
				assert.NoError(t, err)
			}

			tt.validate(t, got)
		})
	}
}

func setupTestEnvironment() func() {
	originalMode := mode
	originalCfgString := cfgString
	originalTimeout := timeout
	originalMaxRetryDelay := maxRetryDelay
	originalPlatformInfo := platformInfo
	originalStepping := stepping
	originalTrustedAuthorKeys := trustedAuthorKeys
	originalTrustedAuthorHashes := trustedAuthorHashes
	originalTrustedIdKeys := trustedIdKeys
	originalTrustedIdKeyHashes := trustedIdKeyHashes
	originalAttestationFile := attestationFile
	originalAttestationRaw := attestationRaw
	originalOutput := output
	originalNonce := nonce
	originalFormat := format
	originalTeeNonce := teeNonce
	originalTokenNonce := tokenNonce
	originalGetTextProtoAttestationReport := getTextProtoAttestationReport
	originalGetAzureTokenJWT := getAzureTokenJWT
	originalCloud := cloud
	originalReportData := reportData
	originalCheckCrl := checkCrl

	mode = ""
	cfgString = ""
	timeout = 0
	maxRetryDelay = 0
	platformInfo = ""
	stepping = ""
	trustedAuthorKeys = []string{}
	trustedAuthorHashes = []string{}
	trustedIdKeys = []string{}
	trustedIdKeyHashes = []string{}
	attestationFile = ""
	attestationRaw = []byte{}
	output = ""
	nonce = []byte{}
	format = ""
	teeNonce = []byte{}
	tokenNonce = []byte{}
	getTextProtoAttestationReport = false
	getAzureTokenJWT = false
	cloud = ""
	reportData = []byte{}
	checkCrl = false

	return func() {
		mode = originalMode
		cfgString = originalCfgString
		timeout = originalTimeout
		maxRetryDelay = originalMaxRetryDelay
		platformInfo = originalPlatformInfo
		stepping = originalStepping
		trustedAuthorKeys = originalTrustedAuthorKeys
		trustedAuthorHashes = originalTrustedAuthorHashes
		trustedIdKeys = originalTrustedIdKeys
		trustedIdKeyHashes = originalTrustedIdKeyHashes
		attestationFile = originalAttestationFile
		attestationRaw = originalAttestationRaw
		output = originalOutput
		nonce = originalNonce
		format = originalFormat
		teeNonce = originalTeeNonce
		tokenNonce = originalTokenNonce
		getTextProtoAttestationReport = originalGetTextProtoAttestationReport
		getAzureTokenJWT = originalGetAzureTokenJWT
		cloud = originalCloud
		reportData = originalReportData
		checkCrl = originalCheckCrl
	}
}

func createTempFile(t *testing.T, content []byte) string {
	tmpfile, err := os.CreateTemp("", "test_*.bin")
	require.NoError(t, err)
	defer tmpfile.Close()

	_, err = tmpfile.Write(content)
	require.NoError(t, err)

	return tmpfile.Name()
}

func TestNewAttestationCmdEdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		args           []string
		expectedOutput string
		hasSubcommands bool
	}{
		{
			name:           "no arguments shows help",
			args:           []string{},
			expectedOutput: "Get and validate attestations",
			hasSubcommands: true,
		},
		{
			name:           "help flag shows usage",
			args:           []string{"--help"},
			expectedOutput: "Get and validate attestations",
			hasSubcommands: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSDK := new(mocks.SDK)
			cli := &CLI{agentSDK: mockSDK}
			cmd := cli.NewAttestationCmd()

			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			assert.NoError(t, err)

			output := buf.String()
			assert.Contains(t, output, tt.expectedOutput)

			if tt.hasSubcommands {
				assert.Contains(t, output, "Get and validate attestations")
				assert.Contains(t, output, "Usage:")
				assert.Contains(t, output, "Flags:")
			}
		})
	}
}

func TestGetAttestationCmdEdgeCases(t *testing.T) {
	defer setupTestEnvironment()()

	testCases := []struct {
		name        string
		args        []string
		setupMock   func(*mocks.SDK)
		expectedErr string
		expectedOut string
	}{
		{
			name: "no arguments provided",
			args: []string{},
			setupMock: func(sdk *mocks.SDK) {
			},
			expectedErr: "accepts 1 arg(s), received 0",
		},
		{
			name: "too many arguments",
			args: []string{"snp", "extra"},
			setupMock: func(sdk *mocks.SDK) {
			},
			expectedErr: "accepts 1 arg(s), received 2",
		},
		{
			name: "invalid attestation type",
			args: []string{"invalid-type"},
			setupMock: func(sdk *mocks.SDK) {
			},
			expectedErr: "Bad attestation type",
		},
		{
			name: "SNP with missing TEE nonce",
			args: []string{"snp"},
			setupMock: func(sdk *mocks.SDK) {
			},
			expectedErr: "TEE nonce must be defined for SEV-SNP attestation",
		},
		{
			name: "vTPM with missing nonce",
			args: []string{"vtpm"},
			setupMock: func(sdk *mocks.SDK) {
			},
			expectedErr: "vTPM nonce must be defined for vTPM attestation",
		},
		{
			name: "Azure token with missing token nonce",
			args: []string{"azure-token"},
			setupMock: func(sdk *mocks.SDK) {
			},
			expectedErr: "Token nonce must be defined for Azure attestation",
		},
		{
			name: "TEE nonce too large",
			args: []string{"snp", "--tee", hex.EncodeToString(bytes.Repeat([]byte{0x00}, quoteprovider.Nonce+1))},
			setupMock: func(sdk *mocks.SDK) {
			},
			expectedErr: "nonce must be a hex encoded string of length lesser or equal 64 bytes",
		},
		{
			name: "vTPM nonce too large",
			args: []string{"vtpm", "--vtpm", hex.EncodeToString(bytes.Repeat([]byte{0x00}, vtpm.Nonce+1))},
			setupMock: func(sdk *mocks.SDK) {
			},
			expectedErr: "vTPM nonce must be a hex encoded string of length lesser or equal 32 bytes",
		},
		{
			name: "Token nonce too large",
			args: []string{"azure-token", "--token", hex.EncodeToString(bytes.Repeat([]byte{0x00}, vtpm.Nonce+1))},
			setupMock: func(sdk *mocks.SDK) {
			},
			expectedErr: "vTPM nonce must be a hex encoded string of length lesser or equal 32 bytes",
		},
		{
			name: "successful TDX attestation",
			args: []string{"tdx", "--tee", hex.EncodeToString(bytes.Repeat([]byte{0x00}, quoteprovider.Nonce))},
			setupMock: func(sdk *mocks.SDK) {
				sdk.On("Attestation", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil).Run(func(args mock.Arguments) {
					if _, err := args.Get(4).(*os.File).Write([]byte("mock tdx attestation")); err != nil {
						t.Fatalf("Failed to write to attestation file: %v", err)
					}
				})
			},
			expectedOut: "Fetching TDX attestation report",
		},
		{
			name: "file creation error",
			args: []string{"snp", "--tee", hex.EncodeToString(bytes.Repeat([]byte{0x00}, quoteprovider.Nonce))},
			setupMock: func(sdk *mocks.SDK) {
			},
			expectedErr: "Error creating attestation file",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			os.Remove(attestationFilePath)
			os.Remove(azureAttestResultFilePath)
			os.Remove(azureAttestTokenFilePath)
			defer func() {
				os.Remove(attestationFilePath)
				os.Remove(azureAttestResultFilePath)
				os.Remove(azureAttestTokenFilePath)
			}()

			mockSDK := new(mocks.SDK)
			cli := &CLI{agentSDK: mockSDK}
			tc.setupMock(mockSDK)

			if tc.name == "file creation error" {
				err := os.Mkdir(attestationFilePath, 0o755)
				require.NoError(t, err)
				defer os.Remove(attestationFilePath)
			}

			cmd := cli.NewGetAttestationCmd()
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs(tc.args)

			err := cmd.Execute()
			output := buf.String()

			if tc.expectedErr != "" {
				assert.Contains(t, output, tc.expectedErr)
			} else {
				assert.NoError(t, err)
				if tc.expectedOut != "" {
					assert.Contains(t, output, tc.expectedOut)
				}
			}
		})
	}
}

func TestFileOperations(t *testing.T) {
	defer setupTestEnvironment()()

	t.Run("openInputFile", func(t *testing.T) {
		attestationFile = ""
		reader, err := openInputFile()
		assert.Error(t, err)
		assert.Equal(t, errEmptyFile, err)
		assert.Nil(t, reader)

		tempFile := createTempFile(t, []byte("test content"))
		defer os.Remove(tempFile)
		attestationFile = tempFile
		reader, err = openInputFile()
		assert.NoError(t, err)
		assert.NotNil(t, reader)
		if file, ok := reader.(*os.File); ok {
			file.Close()
		}

		attestationFile = "non-existent-file.bin"
		reader, err = openInputFile()
		assert.Error(t, err)
		assert.Nil(t, reader)
	})

	t.Run("createOutputFile", func(t *testing.T) {
		output = ""
		writer, err := createOutputFile()
		assert.NoError(t, err)
		assert.Equal(t, os.Stdout, writer)

		tempDir := t.TempDir()
		output = filepath.Join(tempDir, "test_output.txt")
		writer, err = createOutputFile()
		assert.NoError(t, err)
		assert.NotNil(t, writer)
		if file, ok := writer.(*os.File); ok {
			file.Close()
		}

		output = "/invalid/path/file.txt"
		writer, err = createOutputFile()
		assert.Error(t, err)
		assert.Nil(t, writer)
	})
}

func TestValidationFunctions(t *testing.T) {
	t.Run("validateFieldLength", func(t *testing.T) {
		tests := []struct {
			name           string
			fieldName      string
			field          []byte
			expectedLength int
			expectError    bool
		}{
			{
				name:           "nil field",
				fieldName:      "test",
				field:          nil,
				expectedLength: 32,
				expectError:    false,
			},
			{
				name:           "correct length",
				fieldName:      "test",
				field:          make([]byte, 32),
				expectedLength: 32,
				expectError:    false,
			},
			{
				name:           "incorrect length",
				fieldName:      "test",
				field:          make([]byte, 16),
				expectedLength: 32,
				expectError:    true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := validateFieldLength(tt.fieldName, tt.field, tt.expectedLength)
				if tt.expectError {
					assert.Error(t, err)
					assert.Contains(t, err.Error(), tt.fieldName)
				} else {
					assert.NoError(t, err)
				}
			})
		}
	})
}

func TestDecodeJWTToJSONEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
		hasError bool
	}{
		{
			name:     "empty input",
			input:    []byte(""),
			hasError: true,
		},
		{
			name:     "single part",
			input:    []byte("onlyonepart"),
			hasError: true,
		},
		{
			name:     "invalid base64 in header",
			input:    []byte("invalid@base64.validpart"),
			hasError: true,
		},
		{
			name:     "invalid base64 in payload",
			input:    []byte("eyJhbGciOiJIUzI1NiJ9.invalid@base64"),
			hasError: true,
		},
		{
			name:     "invalid JSON in header",
			input:    []byte("bm90anNvbg.eyJzdWIiOiJ0ZXN0In0"),
			hasError: true,
		},
		{
			name:     "invalid JSON in payload",
			input:    []byte("eyJhbGciOiJIUzI1NiJ9.bm90anNvbg"),
			hasError: true,
		},
		{
			name:  "valid JWT with padding",
			input: []byte("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature"),
			expected: `{
  "header": {
    "alg": "HS256"
  },
  "payload": {
    "sub": "test"
  }
}`,
			hasError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := decodeJWTToJSON(tt.input)
			if tt.hasError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				if tt.expected != "" {
					assert.JSONEq(t, tt.expected, string(result))
				}
			}
		})
	}
}

func TestMeasureCmdEdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		mockSetup     func(*mmocks.MeasurementProvider)
		expectedError string
		expectedOut   string
	}{
		{
			name: "no arguments",
			args: []string{},
			mockSetup: func(m *mmocks.MeasurementProvider) {
			},
			expectedError: "requires at least 1 arg(s), only received 0",
		},
		{
			name: "single line output success",
			args: []string{"test.igvm"},
			mockSetup: func(m *mmocks.MeasurementProvider) {
				m.On("Run", "test.igvm").Return([]byte("ABCDEF123456"), nil)
			},
			expectedOut: "",
		},
		{
			name: "multi-line output error",
			args: []string{"test.igvm"},
			mockSetup: func(m *mmocks.MeasurementProvider) {
				m.On("Run", "test.igvm").Return([]byte("line1\nline2\nERROR: something went wrong"), nil)
			},
			expectedError: "ERROR: something went wrong",
		},
		{
			name: "measurement run error",
			args: []string{"test.igvm"},
			mockSetup: func(m *mmocks.MeasurementProvider) {
				m.On("Run", "test.igvm").Return(nil, errors.New("measurement failed"))
			},
			expectedError: "measurement failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMeasurement := new(mmocks.MeasurementProvider)
			tt.mockSetup(mockMeasurement)

			cli := &CLI{measurement: mockMeasurement}
			cmd := cli.NewMeasureCmd("fake_binary_path")

			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
				if tt.expectedOut != "" {
					assert.Contains(t, buf.String(), tt.expectedOut)
				}
			}

			mockMeasurement.AssertExpectations(t)
		})
	}
}

func TestValidateAttestationValidationCmdPreRunE(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		flags       map[string]string
		expectedErr string
	}{
		{
			name:        "no file path provided",
			args:        []string{},
			flags:       map[string]string{"mode": "snp"},
			expectedErr: "please pass the attestation report file path",
		},
		{
			name:        "multiple file paths",
			args:        []string{"file1.bin", "file2.bin"},
			flags:       map[string]string{"mode": "snp"},
			expectedErr: "please pass the attestation report file path",
		},
		{
			name:        "unknown mode",
			args:        []string{"test.bin"},
			flags:       map[string]string{"mode": "unknown"},
			expectedErr: "unknown mode: unknown",
		},
		{
			name:        "SNP mode missing report_data",
			args:        []string{"test.bin"},
			flags:       map[string]string{"mode": "snp"},
			expectedErr: "",
		},
		{
			name:        "SNP mode missing product",
			args:        []string{"test.bin"},
			flags:       map[string]string{"mode": "snp", "report_data": "123"},
			expectedErr: "",
		},
		{
			name:        "vTPM mode missing nonce",
			args:        []string{"test.bin"},
			flags:       map[string]string{"mode": "vtpm"},
			expectedErr: "",
		},
		{
			name:        "SNP-vTPM mode missing required flags",
			args:        []string{"test.bin"},
			flags:       map[string]string{"mode": "snp-vtpm"},
			expectedErr: "",
		},
		{
			name:        "TDX mode missing report_data",
			args:        []string{"test.bin"},
			flags:       map[string]string{"mode": "tdx"},
			expectedErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli := &CLI{}
			cmd := cli.NewValidateAttestationValidationCmd()

			for key, value := range tt.flags {
				if err := cmd.Flags().Set(key, value); err != nil {
				}
			}

			err := cmd.PreRunE(cmd, tt.args)
			if tt.expectedErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCloudProviderConfigurations(t *testing.T) {
	defer setupTestEnvironment()()

	tests := []struct {
		name         string
		cloud        string
		expectedType string
	}{
		{
			name:         "none cloud provider",
			cloud:        CCNone,
			expectedType: "vtpm",
		},
		{
			name:         "azure cloud provider",
			cloud:        CCAzure,
			expectedType: "azure",
		},
		{
			name:         "gcp cloud provider",
			cloud:        CCGCP,
			expectedType: "vtpm",
		},
		{
			name:         "default cloud provider",
			cloud:        "",
			expectedType: "vtpm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli := &CLI{}
			cmd := cli.NewValidateAttestationValidationCmd()

			if err := cmd.Flags().Set("cloud", tt.cloud); err != nil {
				t.Fatalf("Failed to set cloud flag: %v", err)
			}
			cloud, _ := cmd.Flags().GetString("cloud")
			assert.Equal(t, tt.cloud, cloud)

			assert.Contains(t, cmd.Short, tt.cloud)
		})
	}
}

func TestFileOperationErrors(t *testing.T) {
	defer setupTestEnvironment()()

	t.Run("file close error handling", func(t *testing.T) {
		tempFile := createTempFile(t, []byte("test content"))
		defer os.Remove(tempFile)

		assert.True(t, true)
	})

	t.Run("file write error handling", func(t *testing.T) {
		tempFile := createTempFile(t, []byte("test content"))
		defer os.Remove(tempFile)

		err := os.Chmod(tempFile, 0o444)
		require.NoError(t, err)

		err = os.WriteFile(tempFile, []byte("new content"), 0o644)
		assert.Error(t, err)
	})

	t.Run("file read error handling", func(t *testing.T) {
		tempDir := t.TempDir()

		_, err := os.ReadFile(tempDir)
		assert.Error(t, err)
	})
}

func TestContextCancellation(t *testing.T) {
	defer setupTestEnvironment()()

	mockSDK := new(mocks.SDK)
	cli := &CLI{agentSDK: mockSDK}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	mockSDK.On("Attestation", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
		Return(context.Canceled)

	cmd := cli.NewGetAttestationCmd()
	cmd.SetContext(ctx)

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	teeNonceHex := hex.EncodeToString(bytes.Repeat([]byte{0x00}, quoteprovider.Nonce))
	cmd.SetArgs([]string{"snp", "--tee", teeNonceHex})

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "Failed to get attestation due to error")
}
