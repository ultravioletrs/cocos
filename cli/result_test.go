// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{privateKeyFile})
	err = cmd.Execute()
	require.NoError(t, err)

	require.Contains(t, buf.String(), "Computation result retrieved and saved successfully")

	files, err := filepath.Glob("results*.zip")
	require.NoError(t, err)
	require.Len(t, files, 1)

	resultFile, err := os.ReadFile(files[0])
	require.NoError(t, err)
	require.Equal(t, compResult, string(resultFile))

	t.Cleanup(func() {
		for _, file := range files {
			os.Remove(file)
		}
		os.Remove(privateKeyFile)
	})
}

func TestResultsCmd_MultipleExecutions(t *testing.T) {
	mockSDK := new(mocks.SDK)
	mockSDK.On("Result", mock.Anything, mock.Anything).Return([]byte(compResult), nil)
	testCLI := New(mockSDK)

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
	require.Len(t, files, 3)

	t.Cleanup(func() {
		for _, file := range files {
			os.Remove(file)
		}
		os.Remove(privateKeyFile)
	})
}

func TestResultsCmd_MissingPrivateKeyFile(t *testing.T) {
	mockSDK := new(mocks.SDK)
	mockSDK.On("Result", mock.Anything, mock.Anything).Return([]byte(compResult), nil)
	testCLI := New(mockSDK)

	cmd := testCLI.NewResultsCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{"non_existent_private_key.pem"})
	err := cmd.Execute()
	require.NoError(t, err)

	require.Contains(t, buf.String(), "Error reading private key file")
}

func TestResultsCmd_ResultFailure(t *testing.T) {
	mockSDK := new(mocks.SDK)
	mockSDK.On("Result", mock.Anything, mock.Anything).Return(nil, errors.New("error retrieving computation result"))
	testCLI := New(mockSDK)

	err := generateRSAPrivateKeyFile(privateKeyFile)
	require.NoError(t, err)

	cmd := testCLI.NewResultsCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{privateKeyFile})
	err = cmd.Execute()
	require.NoError(t, err)

	require.Contains(t, buf.String(), "error retrieving computation result")
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

	// Simulate failure in saving the result file by making all files read-only
	err = os.Chmod(".", 0o555)
	require.NoError(t, err)

	cmd := testCLI.NewResultsCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{privateKeyFile})
	err = cmd.Execute()
	require.NoError(t, err)

	require.Contains(t, buf.String(), "Error saving computation result file")
	mockSDK.AssertCalled(t, "Result", mock.Anything, mock.Anything)

	t.Cleanup(func() {
		err := os.Chmod(".", 0o755)
		require.NoError(t, err)
		err = os.Remove(privateKeyFile)
		require.NoError(t, err)
	})
}

func TestResultsCmd_InvalidPrivateKey(t *testing.T) {
	mockSDK := new(mocks.SDK)
	mockSDK.On("Result", mock.Anything, mock.Anything).Return([]byte(compResult), nil)
	testCLI := New(mockSDK)

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

func TestGetUniqueFilePath(t *testing.T) {
	prefix := "test"
	ext := ".txt"

	path, err := getUniqueFilePath(prefix, ext)
	require.NoError(t, err)
	require.Equal(t, "test.txt", path)

	_, err = os.Create("test.txt")
	require.NoError(t, err)
	defer os.Remove("test.txt")
	for i := 1; i < 3; i++ {
		fileName := fmt.Sprintf("%s_%d%s", prefix, i, ext)
		_, err := os.Create(fileName)
		require.NoError(t, err)
		defer os.Remove(fileName)
	}

	path, err = getUniqueFilePath(prefix, ext)
	require.NoError(t, err)
	require.Equal(t, "test_3.txt", path)
}
