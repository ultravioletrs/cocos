// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/pkg/sdk/mocks"
)

const compResult = "Test computation result"

func TestResultsCmd_MultipleExecutions(t *testing.T) {
	mockSDK := new(mocks.SDK)
	mockSDK.On("Result", mock.Anything, mock.Anything).Return([]byte(compResult), nil)
	testCLI := CLI{agentSDK: mockSDK}

	err := generateRSAPrivateKeyFile(privateKeyFile)
	require.NoError(t, err)

	cmd := testCLI.NewResultsCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{privateKeyFile})

	for i := 0; i < 3; i++ {
		err = cmd.Execute()
		require.NoError(t, err)
		require.Contains(t, buf.String(), "Computation result retrieved and saved successfully")
		buf.Reset()
	}

	files, err := filepath.Glob("results*.zip")
	require.NoError(t, err)

	t.Cleanup(func() {
		for _, file := range files {
			os.Remove(file)
		}
		os.Remove(privateKeyFile)
	})
}

func TestResultsCmd_InvalidPrivateKey(t *testing.T) {
	mockSDK := new(mocks.SDK)
	mockSDK.On("Result", mock.Anything, mock.Anything).Return([]byte(compResult), nil)
	testCLI := CLI{agentSDK: mockSDK}

	invalidPrivateKey, err := os.CreateTemp("", "invalid_private_key.pem")
	require.NoError(t, err)
	err = invalidPrivateKey.Close()
	require.NoError(t, err)

	t.Cleanup(func() {
		err := os.Remove(invalidPrivateKey.Name())
		require.NoError(t, err)
	})

	cmd := testCLI.NewResultsCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{invalidPrivateKey.Name()})
	err = cmd.Execute()
	require.NoError(t, err)

	require.Contains(t, buf.String(), "Error decoding private key")
	mockSDK.AssertNotCalled(t, "Result", mock.Anything, mock.Anything)
}

func TestResultsCmd(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func(*mocks.SDK)
		setupFiles     func() (string, error)
		connectErr     error
		expectedOutput string
		cleanup        func()
	}{
		{
			name: "successful result retrieval",
			setupMock: func(m *mocks.SDK) {
				m.On("Result", mock.Anything, mock.Anything).Return([]byte(compResult), nil)
			},
			setupFiles: func() (string, error) {
				return privateKeyFile, generateRSAPrivateKeyFile(privateKeyFile)
			},
			expectedOutput: "Computation result retrieved and saved successfully",
			cleanup: func() {
				files, _ := filepath.Glob("results*.zip")
				for _, file := range files {
					os.Remove(file)
				}
				os.Remove(privateKeyFile)
			},
		},
		{
			name: "missing private key file",
			setupMock: func(m *mocks.SDK) {
				m.On("Result", mock.Anything, mock.Anything).Return([]byte(compResult), nil)
			},
			setupFiles: func() (string, error) {
				return "non_existent_private_key.pem", nil
			},
			expectedOutput: "Error reading private key file",
		},
		{
			name: "result retrieval failure",
			setupMock: func(m *mocks.SDK) {
				m.On("Result", mock.Anything, mock.Anything).Return(nil, errors.New("error retrieving computation result"))
			},
			setupFiles: func() (string, error) {
				return privateKeyFile, generateRSAPrivateKeyFile(privateKeyFile)
			},
			expectedOutput: "error retrieving computation result",
			cleanup: func() {
				os.Remove(privateKeyFile)
			},
		},
		{
			name: "save failure",
			setupMock: func(m *mocks.SDK) {
				m.On("Result", mock.Anything, mock.Anything).Return([]byte(compResult), nil)
			},
			setupFiles: func() (string, error) {
				err := generateRSAPrivateKeyFile(privateKeyFile)
				if err != nil {
					return "", err
				}
				// Simulate failure in saving the result file by making all files read-only
				return privateKeyFile, os.Chmod(".", 0o555)
			},
			expectedOutput: "Error saving computation result file",
			cleanup: func() {
				err := os.Chmod(".", 0o755)
				require.NoError(t, err)
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

			file, err := tt.setupFiles()
			require.NoError(t, err)

			cmd := testCLI.NewResultsCmd()
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetArgs([]string{file})
			err = cmd.Execute()
			require.NoError(t, err)

			require.Contains(t, buf.String(), tt.expectedOutput)

			if tt.cleanup != nil {
				tt.cleanup()
			}
		})
	}
}
