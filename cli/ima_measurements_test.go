// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/ultravioletrs/cocos/pkg/sdk/mocks"
)

func TestCLI_NewIMAMeasurementsCmd(t *testing.T) {
	testCases := []struct {
		name              string
		args              []string
		connectErr        error
		mockIMAData       string
		mockError         error
		expectedFilename  string
		expectedOutput    []string
		expectedError     []string
		shouldCreateFile  bool
		fileCreationError bool
		invalidDigestData bool
		setupCustomFile   func(filename string) error
	}{
		{
			name:             "successful_retrieval_default_filename",
			args:             []string{},
			connectErr:       nil,
			mockIMAData:      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			mockError:        nil,
			expectedFilename: imaMeasurementsFilename,
			expectedOutput:   []string{"⏳ Retrieving computation Linux IMA measurements file", "Linux IMA measurements file retrieved and saved successfully", "PCR10 = 0000000000000000000000000000000000000000", "Measurements file verified!"},
			shouldCreateFile: true,
		},
		{
			name:             "successful_retrieval_custom_filename",
			args:             []string{"custom_ima_file.txt"},
			connectErr:       nil,
			mockIMAData:      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			mockError:        nil,
			expectedFilename: "custom_ima_file.txt",
			expectedOutput:   []string{"⏳ Retrieving computation Linux IMA measurements file", "custom_ima_file.txt", "Measurements file verified!"},
			shouldCreateFile: true,
		},
		{
			name:          "connection_error",
			args:          []string{},
			connectErr:    fmt.Errorf("connection failed"),
			expectedError: []string{"Failed to connect to agent: connection failed ❌"},
		},
		{
			name:              "file_creation_error",
			args:              []string{"/invalid/path/file.txt"},
			connectErr:        nil,
			fileCreationError: true,
			expectedError:     []string{"Error creating imaMeasurements file:"},
		},
		{
			name:          "sdk_error",
			args:          []string{},
			connectErr:    nil,
			mockError:     fmt.Errorf("SDK communication failed"),
			expectedError: []string{"Error retrieving Linux IMA measurements file: SDK communication failed ❌"},
		},
		{
			name:             "verification_failure_wrong_pcr",
			args:             []string{},
			connectErr:       nil,
			mockIMAData:      "10 9999999999999999999999999999999999999999 ima-ng sha1:0000000000000000000000000000000000000000 /usr/bin/test",
			mockError:        nil,
			expectedOutput:   []string{"⏳ Retrieving computation Linux IMA measurements file", "Linux IMA measurements file retrieved and saved successfully"},
			expectedError:    []string{"Measurements file not verified ❌"},
			shouldCreateFile: true,
		},
		{
			name:             "empty_measurements_file",
			args:             []string{},
			connectErr:       nil,
			mockIMAData:      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			mockError:        nil,
			expectedOutput:   []string{"⏳ Retrieving computation Linux IMA measurements file", "Linux IMA measurements file retrieved and saved successfully", "Measurements file verified!"},
			shouldCreateFile: true,
		},
		{
			name:             "measurements_with_non_pcr10_entries",
			args:             []string{},
			connectErr:       nil,
			mockIMAData:      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			mockError:        nil,
			expectedOutput:   []string{"⏳ Retrieving computation Linux IMA measurements file", "Linux IMA measurements file retrieved and saved successfully", "Measurements file verified!"},
			shouldCreateFile: true,
		},
		{
			name:             "measurements_with_zero_digest_replacement",
			args:             []string{},
			connectErr:       nil,
			mockIMAData:      "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			mockError:        nil,
			expectedOutput:   []string{"⏳ Retrieving computation Linux IMA measurements file", "Linux IMA measurements file retrieved and saved successfully", "Measurements file verified!"},
			shouldCreateFile: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockSDK := new(mocks.SDK)

			cli := &CLI{
				agentSDK:   mockSDK,
				connectErr: tc.connectErr,
			}

			if tc.connectErr == nil && !tc.fileCreationError {
				mockSDK.On("IMAMeasurements", mock.Anything, mock.Anything).Return([]byte(tc.mockIMAData), tc.mockError)
			}

			cmd := cli.NewIMAMeasurementsCmd()

			var output bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetErr(&output)

			expectedFilename := tc.expectedFilename
			if expectedFilename == "" {
				if len(tc.args) > 0 {
					expectedFilename = tc.args[0]
				} else {
					expectedFilename = imaMeasurementsFilename
				}
			}

			if tc.setupCustomFile != nil {
				err := tc.setupCustomFile(expectedFilename)
				assert.NoError(t, err)
			}

			cmd.SetArgs(tc.args)
			cmd.Execute()

			outputStr := output.String()

			for _, expectedMsg := range tc.expectedOutput {
				assert.Contains(t, outputStr, expectedMsg, "Expected output message not found")
			}

			for _, expectedErr := range tc.expectedError {
				assert.Contains(t, outputStr, expectedErr, "Expected error message not found")
			}

			if tc.shouldCreateFile && tc.connectErr == nil && !tc.fileCreationError && tc.mockError == nil {
				if _, err := os.Stat(expectedFilename); err == nil {
					os.Remove(expectedFilename)
				}
			}

			if tc.connectErr == nil && !tc.fileCreationError {
				mockSDK.AssertExpectations(t)
			}
		})
	}
}
