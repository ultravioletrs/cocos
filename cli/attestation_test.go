// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/pkg/sdk/mocks"
)

func TestNewAttestationCmd(t *testing.T) {
	cli := &CLI{}
	cmd := cli.NewAttestationCmd()

	assert.Equal(t, "attestation [command]", cmd.Use)
	assert.Equal(t, "Get and validate attestations", cmd.Short)
}

func TestNewGetAttestationCmd(t *testing.T) {
	mockSDK := new(mocks.SDK)
	cli := &CLI{agentSDK: mockSDK}
	cmd := cli.NewGetAttestationCmd()
	var buf bytes.Buffer

	cmd.SetOutput(&buf)

	assert.Equal(t, "get", cmd.Use)
	assert.Equal(t, "Retrieve attestation information from agent. Report data expected in hex enoded string of length 64 bytes.", cmd.Short)

	reportData := bytes.Repeat([]byte{0x01}, agent.ReportDataSize)
	mockSDK.On("Attestation", mock.Anything, [agent.ReportDataSize]byte(reportData)).Return([]byte("mock attestation"), nil)

	cmd.SetArgs([]string{hex.EncodeToString(reportData)})
	err := cmd.Execute()
	assert.NoError(t, err)

	assert.Contains(t, buf.String(), "Attestation result retrieved and saved successfully!")

	os.Remove(attestationFilePath)
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
