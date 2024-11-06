// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/pkg/sdk/mocks"
)

const algorithmFile = "test_algo_file.py"

func generateRSAPrivateKeyFile(fileName string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	privKeyFile, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer privKeyFile.Close()

	privateKeyPEM := &pem.Block{
		Type:  rsaKeyType,
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	err = pem.Encode(privKeyFile, privateKeyPEM)
	if err != nil {
		return err
	}

	return nil
}

func TestAlgorithmCmd_Success(t *testing.T) {
	mockSDK := new(mocks.SDK)
	mockSDK.On("Algo", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	testCLI := CLI{agentSDK: mockSDK}

	err := os.WriteFile(algorithmFile, []byte("test algorithm"), 0o644)
	require.NoError(t, err)

	err = generateRSAPrivateKeyFile(privateKeyFile)
	require.NoError(t, err)

	cmd := testCLI.NewAlgorithmCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{algorithmFile, privateKeyFile})
	err = cmd.Execute()
	require.NoError(t, err)

	require.Contains(t, buf.String(), "Successfully uploaded algorithm")
	t.Cleanup(func() {
		os.Remove(privateKeyFile)
		os.Remove(algorithmFile)
	})
}

func TestAlgorithmCmd_MissingAlgorithmFile(t *testing.T) {
	mockSDK := new(mocks.SDK)
	mockSDK.On("Algo", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	testCLI := CLI{agentSDK: mockSDK}

	cmd := testCLI.NewAlgorithmCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	cmd.SetArgs([]string{"non_existent_algo_file.py", privateKeyFile})
	err := cmd.Execute()
	require.NoError(t, err)

	require.Contains(t, buf.String(), "Error reading algorithm file")
}

func TestAlgorithmCmd_MissingPrivateKeyFile(t *testing.T) {
	mockSDK := new(mocks.SDK)
	mockSDK.On("Algo", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	testCLI := CLI{agentSDK: mockSDK}

	err := os.WriteFile(algorithmFile, []byte("test algorithm"), 0o644)
	require.NoError(t, err)

	cmd := testCLI.NewAlgorithmCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetArgs([]string{algorithmFile, "non_existent_private_key.pem"})
	err = cmd.Execute()
	require.NoError(t, err)

	require.Contains(t, buf.String(), "Error reading private key file")
	t.Cleanup(func() {
		os.Remove(algorithmFile)
	})
}

func TestAlgorithmCmd_UploadFailure(t *testing.T) {
	mockSDK := new(mocks.SDK)
	mockSDK.On("Algo", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("failed to upload algorithm due to error"))
	testCLI := CLI{agentSDK: mockSDK}

	err := os.WriteFile(algorithmFile, []byte("test algorithm"), 0o644)
	require.NoError(t, err)

	err = generateRSAPrivateKeyFile(privateKeyFile)
	require.NoError(t, err)

	cmd := testCLI.NewAlgorithmCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	cmd.SetArgs([]string{algorithmFile, privateKeyFile})
	err = cmd.Execute()
	require.NoError(t, err)

	require.Contains(t, buf.String(), "Failed to upload algorithm")

	t.Cleanup(func() {
		os.Remove(privateKeyFile)
		os.Remove(algorithmFile)
	})
}

func TestAlgorithmCmd_InvalidPrivateKey(t *testing.T) {
	mockSDK := new(mocks.SDK)
	mockSDK.On("Algo", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	testCLI := CLI{agentSDK: mockSDK}

	err := os.WriteFile(algorithmFile, []byte("test algorithm"), 0o644)
	require.NoError(t, err)

	privKeyFile, err := os.Create(privateKeyFile)
	require.NoError(t, err)
	defer privKeyFile.Close()

	_, err = privKeyFile.WriteString("invalid private key")
	require.NoError(t, err)

	cmd := testCLI.NewAlgorithmCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)

	cmd.SetArgs([]string{algorithmFile, privateKeyFile})
	err = cmd.Execute()
	require.NoError(t, err)

	require.Contains(t, buf.String(), "Error decoding private key")

	t.Cleanup(func() {
		os.Remove(algorithmFile)
		os.Remove(privateKeyFile)
	})
}
