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
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/pkg/sdk/mocks"
)

const algorithmFile = "test_algo_file.py"

func captureLogOutput(f func()) string {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	f()
	return buf.String()
}

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
	testCLI := New(mockSDK)

	err := os.WriteFile(algorithmFile, []byte("test algorithm"), 0o644)
	require.NoError(t, err)

	err = generateRSAPrivateKeyFile(privateKeyFile)
	require.NoError(t, err)

	cmd := testCLI.NewAlgorithmCmd()
	output := captureLogOutput(func() {
		cmd.SetArgs([]string{algorithmFile, privateKeyFile})
		err = cmd.Execute()
		require.NoError(t, err)
	})

	require.Contains(t, output, "Successfully uploaded algorithm")
	t.Cleanup(func() {
		os.Remove(privateKeyFile)
		os.Remove(algorithmFile)
	})
}

func TestAlgorithmCmd_MissingAlgorithmFile(t *testing.T) {
	mockSDK := new(mocks.SDK)
	mockSDK.On("Algo", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	testCLI := New(mockSDK)

	cmd := testCLI.NewAlgorithmCmd()

	output := captureLogOutput(func() {
		cmd.SetArgs([]string{"non_existent_algo_file.py", privateKeyFile})
		err := cmd.Execute()
		require.NoError(t, err)
	})

	require.Contains(t, output, "Error reading algorithm file")
}

func TestAlgorithmCmd_MissingPrivateKeyFile(t *testing.T) {
	mockSDK := new(mocks.SDK)
	mockSDK.On("Algo", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	testCLI := New(mockSDK)

	err := os.WriteFile(algorithmFile, []byte("test algorithm"), 0o644)
	require.NoError(t, err)

	cmd := testCLI.NewAlgorithmCmd()

	output := captureLogOutput(func() {
		cmd.SetArgs([]string{algorithmFile, "non_existent_private_key.pem"})
		err = cmd.Execute()
		require.NoError(t, err)
	})

	require.Contains(t, output, "Error reading private key file")
	t.Cleanup(func() {
		os.Remove(algorithmFile)
	})
}

func TestAlgorithmCmd_UploadFailure(t *testing.T) {
	mockSDK := new(mocks.SDK)
	mockSDK.On("Algo", mock.Anything, mock.Anything, mock.Anything).Return(errors.New("failed to upload algorithm due to error"))
	testCLI := New(mockSDK)

	err := os.WriteFile(algorithmFile, []byte("test algorithm"), 0o644)
	require.NoError(t, err)

	err = generateRSAPrivateKeyFile(privateKeyFile)
	require.NoError(t, err)

	cmd := testCLI.NewAlgorithmCmd()

	output := captureLogOutput(func() {
		cmd.SetArgs([]string{algorithmFile, privateKeyFile})
		err = cmd.Execute()
		require.NoError(t, err)
	})

	require.Contains(t, output, "Failed to upload algorithm")

	t.Cleanup(func() {
		os.Remove(privateKeyFile)
		os.Remove(algorithmFile)
	})
}
