// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/pkg/sdk/mocks"
)

const compResult = "Test computation result"

func TestResultsCmd_Success(t *testing.T) {
	mockSDK := new(mocks.SDK)
	mockSDK.On("Result", mock.Anything, mock.Anything).Return([]byte(compResult), nil)
	testCLI := New(mockSDK)

	err := generateRSAPrivateKeyFile(privateKeyFile)
	require.NoError(t, err)

	cmd := testCLI.NewResultsCmd()
	output := captureLogOutput(func() {
		cmd.SetArgs([]string{privateKeyFile})
		err = cmd.Execute()
		require.NoError(t, err)
	})

	require.Contains(t, output, "Computation result retrieved and saved successfully")

	resultFile, err := os.ReadFile("results.zip")
	require.NoError(t, err)
	require.Equal(t, compResult, string(resultFile))

	t.Cleanup(func() {
		os.Remove("results.zip")
		os.Remove(privateKeyFile)
	})
}

func TestResultsCmd_MissingPrivateKeyFile(t *testing.T) {
	mockSDK := new(mocks.SDK)
	mockSDK.On("Result", mock.Anything, mock.Anything).Return([]byte(compResult), nil)
	testCLI := New(mockSDK)

	cmd := testCLI.NewResultsCmd()
	output := captureLogOutput(func() {
		cmd.SetArgs([]string{"non_existent_private_key.pem"})
		err := cmd.Execute()
		require.NoError(t, err)
	})

	require.Contains(t, output, "Error reading private key file")
}

func TestResultsCmd_ResultFailure(t *testing.T) {
	mockSDK := new(mocks.SDK)
	mockSDK.On("Result", mock.Anything, mock.Anything).Return(nil, errors.New("error retrieving computation result"))
	testCLI := New(mockSDK)

	err := generateRSAPrivateKeyFile(privateKeyFile)
	require.NoError(t, err)

	cmd := testCLI.NewResultsCmd()
	output := captureLogOutput(func() {
		cmd.SetArgs([]string{privateKeyFile})
		err = cmd.Execute()
		require.NoError(t, err)
	})

	require.Contains(t, output, "error retrieving computation result")
	mockSDK.AssertCalled(t, "Result", mock.Anything, mock.Anything)
	t.Cleanup(func() {
		os.Remove(privateKeyFile)
	})
}

func TestResultsCmd_SaveFailure(t *testing.T) {
	mockSDK := new(mocks.SDK)
	mockSDK.On("Result", mock.Anything, mock.Anything).Return([]byte(compResult), nil)
	testCLI := New(mockSDK)

	err := generateRSAPrivateKeyFile(privateKeyFile)
	require.NoError(t, err)

	// Simulate failure in saving the result file by making a directory with the same name as the result file
	err = os.Mkdir("results.zip", 0o755)
	require.NoError(t, err)

	cmd := testCLI.NewResultsCmd()
	output := captureLogOutput(func() {
		cmd.SetArgs([]string{privateKeyFile})
		err := cmd.Execute()
		require.NoError(t, err)
	})

	require.Contains(t, output, "Error saving computation result to results.zip")
	mockSDK.AssertCalled(t, "Result", mock.Anything, mock.Anything)

	t.Cleanup(func() {
		os.Remove("results.zip")
		os.Remove(privateKeyFile)
	})
}
