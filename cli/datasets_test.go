// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/pkg/sdk/mocks"
)

func createTempDatasetFile(content string) (string, error) {
	tmpFile, err := os.CreateTemp("", "dataset-*.txt")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	_, err = tmpFile.WriteString(content)
	if err != nil {
		return "", err
	}
	return tmpFile.Name(), nil
}

func TestDatasetsCmd(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func(*mocks.SDK)
		setupFiles     func() (string, error)
		connectErr     error
		expectedOutput string
		cleanup        func(string, string)
	}{
		{
			name: "successful upload",
			setupMock: func(m *mocks.SDK) {
				m.On("Data", mock.Anything, mock.Anything, mock.Anything).Return(nil)
			},
			setupFiles: func() (string, error) {
				datasetFile, err := createTempDatasetFile("test dataset content")
				if err != nil {
					return "", err
				}
				err = generateRSAPrivateKeyFile(privateKeyFile)
				return datasetFile, err
			},
			expectedOutput: "Successfully uploaded dataset",
			cleanup: func(datasetFile, privateKeyFile string) {
				os.Remove(datasetFile)
				os.Remove(privateKeyFile)
			},
		},
		{
			name: "missing dataset file",
			setupMock: func(m *mocks.SDK) {
				m.On("Data", mock.Anything, mock.Anything, mock.Anything).Return(nil)
			},
			setupFiles: func() (string, error) {
				return "", nil
			},
			expectedOutput: "Error reading dataset file",
		},
		{
			name: "missing private key file",
			setupMock: func(m *mocks.SDK) {
				m.On("Data", mock.Anything, mock.Anything, mock.Anything).Return(nil)
			},
			setupFiles: func() (string, error) {
				return createTempDatasetFile("test dataset content")
			},
			expectedOutput: "Error reading private key file",
			cleanup: func(datasetFile, _ string) {
				os.Remove(datasetFile)
			},
		},
		{
			name: "upload failure",
			setupMock: func(m *mocks.SDK) {
				m.On("Data", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("failed to upload algorithm due to error"))
			},
			setupFiles: func() (string, error) {
				datasetFile, err := createTempDatasetFile("test dataset content")
				if err != nil {
					return "", err
				}
				err = generateRSAPrivateKeyFile(privateKeyFile)
				return datasetFile, err
			},
			expectedOutput: "Failed to upload dataset due to error",
			cleanup: func(datasetFile, privateKeyFile string) {
				os.Remove(datasetFile)
				os.Remove(privateKeyFile)
			},
		},
		{
			name: "invalid private key",
			setupMock: func(m *mocks.SDK) {
				m.On("Data", mock.Anything, mock.Anything, mock.Anything).Return(nil)
			},
			setupFiles: func() (string, error) {
				datasetFile, err := createTempDatasetFile("test dataset content")
				if err != nil {
					return "", err
				}
				err = os.WriteFile(privateKeyFile, []byte("invalid private key"), 0o644)
				return datasetFile, err
			},
			expectedOutput: "Error decoding private key",
			cleanup: func(datasetFile, privateKeyFile string) {
				os.Remove(datasetFile)
				os.Remove(privateKeyFile)
			},
		},
		{
			name: "connection error",
			setupMock: func(m *mocks.SDK) {
			},
			setupFiles:     func() (string, error) { return "", nil },
			connectErr:     errors.New("failed to connect to agent"),
			expectedOutput: "Failed to connect to agent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSDK := new(mocks.SDK)
			if tt.setupMock != nil {
				tt.setupMock(mockSDK)
			}

			testCLI := CLI{
				agentSDK:   mockSDK,
				connectErr: tt.connectErr,
			}

			datasetFile, err := tt.setupFiles()
			require.NoError(t, err)

			cmd := testCLI.NewDatasetsCmd()
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetArgs([]string{datasetFile, privateKeyFile})
			err = cmd.Execute()
			require.NoError(t, err)

			require.Contains(t, buf.String(), tt.expectedOutput)

			if tt.cleanup != nil {
				tt.cleanup(datasetFile, privateKeyFile)
			}
		})
	}
}
