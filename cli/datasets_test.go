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

func TestDatasetsCmd_Success(t *testing.T) {
	mockSDK := new(mocks.SDK)
	mockSDK.On("Data", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	testCLI := New(mockSDK)

	datasetFile, err := createTempDatasetFile("test dataset content")
	require.NoError(t, err)

	err = generateRSAPrivateKeyFile(privateKeyFile)
	require.NoError(t, err)

	cmd := testCLI.NewDatasetsCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	cmd.SetArgs([]string{datasetFile, privateKeyFile})
	err = cmd.Execute()
	require.NoError(t, err)

	require.Contains(t, buf.String(), "Successfully uploaded dataset")
	mockSDK.AssertCalled(t, "Data", mock.Anything, mock.Anything, mock.Anything)

	t.Cleanup(func() {
		os.Remove(datasetFile)
		os.Remove(privateKeyFile)
	})
}

func TestDatasetsCmd_MissingDatasetFile(t *testing.T) {
	mockSDK := new(mocks.SDK)
	mockSDK.On("Data", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	testCLI := New(mockSDK)

	cmd := testCLI.NewDatasetsCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	cmd.SetArgs([]string{"non_existent_dataset.txt", privateKeyFile})
	err := cmd.Execute()
	require.NoError(t, err)

	require.Contains(t, buf.String(), "Error reading dataset file")
}

func TestDatasetsCmd_MissingPrivateKeyFile(t *testing.T) {
	mockSDK := new(mocks.SDK)
	mockSDK.On("Data", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	testCLI := New(mockSDK)

	datasetFile, err := createTempDatasetFile("test dataset content")
	require.NoError(t, err)

	cmd := testCLI.NewDatasetsCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	cmd.SetArgs([]string{datasetFile, "non_existent_private_key.pem"})
	err = cmd.Execute()
	require.NoError(t, err)

	require.Contains(t, buf.String(), "Error reading private key file")
	t.Cleanup(func() {
		os.Remove(datasetFile)
	})
}

func TestDatasetsCmd_UploadFailure(t *testing.T) {
	mockSDK := new(mocks.SDK)
	mockSDK.On("Data", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("failed to upload algorithm due to error"))
	testCLI := New(mockSDK)

	datasetFile, err := createTempDatasetFile("test dataset content")
	require.NoError(t, err)

	err = generateRSAPrivateKeyFile(privateKeyFile)
	require.NoError(t, err)

	cmd := testCLI.NewDatasetsCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	cmd.SetArgs([]string{datasetFile, privateKeyFile})
	err = cmd.Execute()
	require.NoError(t, err)

	require.Contains(t, buf.String(), "Failed to upload dataset due to error")
	t.Cleanup(func() {
		os.Remove(datasetFile)
		os.Remove(privateKeyFile)
	})
}
