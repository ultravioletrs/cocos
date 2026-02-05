// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"encoding/hex"
	"os"
	"testing"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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

	// Since NewAttestationCmd just prints help, we can check basic execution
	cmd.SetArgs([]string{"--help"})
	err := cmd.Execute()
	assert.NoError(t, err)
}

func TestNewGetAttestationCmd(t *testing.T) {
	teeNonce := hex.EncodeToString(bytes.Repeat([]byte{0x00}, vtpm.SEVNonce))
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
			expectedOut:  "Attestation retrieved and saved successfully!",
		},
		{
			name:         "successful vTPM attestation retrieval",
			args:         []string{"vtpm", "--vtpm", vtpmNonce},
			mockResponse: []byte("mock attestation"),
			mockError:    nil,
			expectedOut:  "Attestation retrieved and saved successfully!",
		},
		{
			name:         "successful SNP-vTPM attestation retrieval",
			args:         []string{"snp-vtpm", "--tee", teeNonce, "--vtpm", vtpmNonce},
			mockResponse: []byte("mock attestation"),
			mockError:    nil,
			expectedOut:  "Attestation retrieved and saved successfully!",
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
			expectedOut:  "Fetching Azure token\nAttestation retrieved and saved successfully!\n",
		},
		{
			name:         "failed to retrieve Azure token",
			args:         []string{"azure-token", "--token", tokenNonce},
			mockResponse: nil,
			mockError:    errors.New("error"),
			expectedErr:  "Fetching Azure token\nFailed to get attestation token due to error: error ❌\n",
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

			mockSDK.On("Attestation", mock.Anything, [vtpm.SEVNonce]byte(bytes.Repeat([]byte{0x00}, vtpm.SEVNonce)), [vtpm.Nonce]byte(bytes.Repeat([]byte{0x00}, vtpm.Nonce)), mock.Anything, mock.Anything).Return(tc.mockError).Run(func(args mock.Arguments) {
				_, err := args.Get(4).(*os.File).Write(tc.mockResponse)
				require.NoError(t, err)
			})

			mockSDK.On("AttestationToken", mock.Anything, [vtpm.Nonce]byte(bytes.Repeat([]byte{0x00}, vtpm.Nonce)), mock.Anything, mock.Anything).Return(tc.mockError).Run(func(args mock.Arguments) {
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

func TestNewValidateAttestationValidationCmd(t *testing.T) {
	cli := &CLI{}
	cmd := cli.NewValidateAttestationValidationCmd()

	assert.Equal(t, "validate", cmd.Use)
	assert.Contains(t, cmd.Short, "Deprecated")

	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.Execute()
	assert.Contains(t, buf.String(), "deprecated")
}
