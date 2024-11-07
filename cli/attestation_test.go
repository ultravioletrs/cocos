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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/agent"
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

	cmd.SetOutput(&buf)

	reportData := bytes.Repeat([]byte{0x01}, agent.ReportDataSize)
	mockSDK.On("Attestation", mock.Anything, [agent.ReportDataSize]byte(reportData), mock.Anything).Return(nil)

	cmd.SetArgs([]string{hex.EncodeToString(reportData)})
	err := cmd.Execute()
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "Get and validate attestations")
}

func TestNewGetAttestationCmd(t *testing.T) {
	validattestation, err := os.ReadFile("../attestation.bin")
	require.NoError(t, err)
	testCases := []struct {
		name         string
		args         []string
		mockResponse []byte
		mockError    error
		expectedErr  string
		expectedOut  string
	}{
		{
			name:         "successful attestation retrieval",
			args:         []string{hex.EncodeToString(bytes.Repeat([]byte{0x01}, agent.ReportDataSize))},
			mockResponse: []byte("mock attestation"),
			mockError:    nil,
			expectedOut:  "Attestation result retrieved and saved successfully!",
		},
		{
			name:         "invalid report data (decoding error)",
			args:         []string{"invalid"},
			mockResponse: nil,
			mockError:    errors.New("error"),
			expectedErr:  "Error decoding report data",
		},
		{
			name:         "invalid report data size",
			args:         []string{hex.EncodeToString(bytes.Repeat([]byte{0x01}, 32))},
			mockResponse: nil,
			mockError:    errors.New("error"),
			expectedErr:  "report data must be a hex encoded string of length 64 bytes",
		},
		{
			name:         "invalid report data hex",
			args:         []string{"invalid"},
			mockResponse: nil,
			mockError:    errors.New("error"),
			expectedErr:  "Error decoding report data",
		},
		{
			name:         "failed to get attestation",
			args:         []string{hex.EncodeToString(bytes.Repeat([]byte{0x01}, agent.ReportDataSize))},
			mockResponse: nil,
			mockError:    errors.New("error"),
			expectedErr:  "Failed to get attestation due to error",
		},
		{
			name:         "JSON report error",
			args:         []string{hex.EncodeToString(bytes.Repeat([]byte{0x01}, agent.ReportDataSize)), "--json"},
			mockResponse: []byte("mock attestation"),
			mockError:    nil,
			expectedErr:  "Error converting attestation to json",
		},
		{
			name:         "successful JSON report",
			args:         []string{hex.EncodeToString(bytes.Repeat([]byte{0x01}, agent.ReportDataSize)), "--json"},
			mockResponse: validattestation,
			mockError:    nil,
			expectedOut:  "Attestation result retrieved and saved successfully!",
		},
		{
			name:         "connection error",
			args:         []string{hex.EncodeToString(bytes.Repeat([]byte{0x01}, agent.ReportDataSize))},
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
			cmd.SetOutput(&buf)

			mockSDK.On("Attestation", mock.Anything, [agent.ReportDataSize]byte(bytes.Repeat([]byte{0x01}, agent.ReportDataSize)), mock.Anything).Return(tc.mockError).Run(func(args mock.Arguments) {
				_, err := args.Get(2).(*os.File).Write(tc.mockResponse)
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

func TestNewValidateAttestationValidationCmd(t *testing.T) {
	cli := &CLI{}
	cmd := cli.NewValidateAttestationValidationCmd()

	assert.Equal(t, "validate", cmd.Use)
	assert.Equal(t, "Validate and verify attestation information. The report is provided as a file path.", cmd.Short)

	assert.Equal(t, fmt.Sprint(defaultMinimumTcb), cmd.Flag("minimum_tcb").Value.String())
	assert.Equal(t, fmt.Sprint(defaultMinimumLaunchTcb), cmd.Flag("minimum_lauch_tcb").Value.String())
	assert.Equal(t, fmt.Sprint(defaultGuestPolicy), cmd.Flag("guest_policy").Value.String())
	assert.Equal(t, fmt.Sprint(defaultMinimumGuestSvn), cmd.Flag("minimum_guest_svn").Value.String())
	assert.Equal(t, fmt.Sprint(defaultMinimumBuild), cmd.Flag("minimum_build").Value.String())
	assert.Equal(t, defaultCheckCrl, cmd.Flag("check_crl").Value.String() == "true")
	assert.Equal(t, fmt.Sprint(defaultTimeout), cmd.Flag("timeout").Value.String())
	assert.Equal(t, fmt.Sprint(defaultMaxRetryDelay), cmd.Flag("max_retry_delay").Value.String())
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

	err = parseFiles()
	assert.NoError(t, err)
	assert.Equal(t, []byte("test attestation"), attestation)
	assert.Len(t, cfg.Policy.TrustedAuthorKeys, 1)
	assert.Len(t, cfg.Policy.TrustedIdKeys, 1)

	os.Remove(attestationFile)
	os.Remove(authorKeyFile)
	os.Remove(idKeyFile)

	attestationFile = "non_existent_file.bin"
	err = parseFiles()
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
