// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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
			args:         []string{"vtpm", "-t", hex.EncodeToString(bytes.Repeat([]byte{0x00}, 33))},
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
			args:         []string{"snp", "-e", teeNonce},
			mockResponse: nil,
			mockError:    errors.New("error"),
			expectedErr:  "Failed to get attestation due to error",
		},
		{
			name:         "Textproto report error",
			args:         []string{"snp", "-e", teeNonce, "--textproto"},
			mockResponse: []byte("mock attestation"),
			mockError:    nil,
			expectedErr:  "Error converting attestation to textproto",
		},
		{
			name:         "successful Textproto report",
			args:         []string{"snp", "-e", teeNonce, "--textproto"},
			mockResponse: validattestation,
			mockError:    nil,
			expectedOut:  "Attestation result retrieved and saved successfully!",
		},
		{
			name:         "connection error",
			args:         []string{"snp", "-e", teeNonce},
			mockResponse: nil,
			mockError:    errors.New("failed to connect to agent"),
			expectedErr:  "Failed to connect to agent",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(func() {
				os.Remove(attestationFilePath)
				os.Remove(attestationJson)
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
	expectedMessage := fmt.Sprintf("Validate and verify attestation information. You can define the confidential computing cloud provider (%s, %s, %s; %s is the default) and can choose from 3 modes: %s, %s and %s. Default mode is %s.", CCNone, CCAzure, CCGCP, CCNone, SNP, VTPM, SNPvTPM, SNP)
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

type MockMeasurement struct {
	mock.Mock
}

func (m *MockMeasurement) Run(igvmBinaryPath string) ([]byte, error) {
	args := m.Called(igvmBinaryPath)
	return nil, args.Error(0)
}

func (m *MockMeasurement) Stop() error {
	args := m.Called()
	return args.Error(0)
}

func TestNewMeasureCmd_RunSuccess(t *testing.T) {
	cliInstance := &CLI{}
	mockMeasurement := new(MockMeasurement)
	cliInstance.measurement = mockMeasurement

	mockMeasurement.On("Run", "testfile.igvm").Return(nil)

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
	mockMeasurement := new(MockMeasurement)
	cliInstance.measurement = mockMeasurement
	expectedError := errors.New("mocked measurement error")

	mockMeasurement.On("Run", "testfile.igvm").Return(expectedError)

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

func TestParseConfig(t *testing.T) {
	cfgString = ""
	err := parseConfig()
	assert.NoError(t, err)
	assert.NotNil(t, cfg.RootOfTrust)
	assert.NotNil(t, cfg.Policy)

	cfgString = `{"rootOfTrust":{"product":"test_product"},"policy":{"minimumGuestSvn":1}}`
	err = parseConfig()
	assert.NoError(t, err)
	assert.Equal(t, "test_product", cfg.RootOfTrust.Product)
	assert.Equal(t, uint32(1), cfg.Policy.MinimumGuestSvn)

	cfgString = `{"invalid_json"`
	err = parseConfig()
	assert.Error(t, err)
}

func TestParseHashes(t *testing.T) {
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
	assert.Equal(t, []byte("test attestation"), attestation)
	assert.Len(t, cfg.Policy.TrustedAuthorKeys, 1)
	assert.Len(t, cfg.Policy.TrustedIdKeys, 1)

	os.Remove(attestationFile)
	os.Remove(authorKeyFile)
	os.Remove(idKeyFile)

	attestationFile = "non_existent_file.bin"
	err = parseAttestationFile()
	assert.Error(t, err)
}

func TestParseUints(t *testing.T) {
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

func TestValidateInput(t *testing.T) {
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

func TestGetBase(t *testing.T) {
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
			got, err := attesationToJSON(tt.input)
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
			got, err := attesationFromJSON(tt.input)
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
	jsonData, err := attesationToJSON(originalReport)
	require.NoError(t, err)
	require.NotNil(t, jsonData)

	roundTripReport, err := attesationFromJSON(jsonData)
	require.NoError(t, err)
	require.NotNil(t, roundTripReport)
}
