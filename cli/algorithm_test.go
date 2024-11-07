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

func TestAlgorithmCmd(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func(*mocks.SDK)
		setupFiles     func() error
		args           []string
		connectErr     error
		expectedOutput string
		cleanup        func()
	}{
		{
			name: "successful upload",
			setupMock: func(m *mocks.SDK) {
				m.On("Algo", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
			},
			setupFiles: func() error {
				if err := os.WriteFile(algorithmFile, []byte("test algorithm"), 0o644); err != nil {
					return err
				}
				return generateRSAPrivateKeyFile(privateKeyFile)
			},
			args:           []string{algorithmFile, privateKeyFile},
			expectedOutput: "Successfully uploaded algorithm",
			cleanup: func() {
				os.Remove(privateKeyFile)
				os.Remove(algorithmFile)
			},
		},
		{
			name: "missing algorithm file",
			setupMock: func(m *mocks.SDK) {
				m.On("Algo", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
			},
			args:           []string{"non_existent_algo_file.py", privateKeyFile},
			expectedOutput: "Error reading algorithm file",
		},
		{
			name: "missing private key file",
			setupMock: func(m *mocks.SDK) {
				m.On("Algo", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
			},
			setupFiles: func() error {
				return os.WriteFile(algorithmFile, []byte("test algorithm"), 0o644)
			},
			args:           []string{algorithmFile, "non_existent_private_key.pem"},
			expectedOutput: "Error reading private key file",
			cleanup: func() {
				os.Remove(algorithmFile)
			},
		},
		{
			name: "upload failure",
			setupMock: func(m *mocks.SDK) {
				m.On("Algo", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("failed to upload algorithm due to error"))
			},
			setupFiles: func() error {
				if err := os.WriteFile(algorithmFile, []byte("test algorithm"), 0o644); err != nil {
					return err
				}
				return generateRSAPrivateKeyFile(privateKeyFile)
			},
			args:           []string{algorithmFile, privateKeyFile},
			expectedOutput: "Failed to upload algorithm",
			cleanup: func() {
				os.Remove(privateKeyFile)
				os.Remove(algorithmFile)
			},
		},
		{
			name: "invalid private key",
			setupMock: func(m *mocks.SDK) {
				m.On("Algo", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
			},
			setupFiles: func() error {
				if err := os.WriteFile(algorithmFile, []byte("test algorithm"), 0o644); err != nil {
					return err
				}
				privKeyFile, err := os.Create(privateKeyFile)
				if err != nil {
					return err
				}
				defer privKeyFile.Close()
				_, err = privKeyFile.WriteString("invalid private key")
				return err
			},
			args:           []string{algorithmFile, privateKeyFile},
			expectedOutput: "Error decoding private key",
			cleanup: func() {
				os.Remove(algorithmFile)
				os.Remove(privateKeyFile)
			},
		},
		{
			name: "connection error",
			setupMock: func(m *mocks.SDK) {
			},
			connectErr:     errors.New("failed to connect to agent"),
			args:           []string{algorithmFile, privateKeyFile},
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

			if tt.setupFiles != nil {
				err := tt.setupFiles()
				require.NoError(t, err)
			}

			cmd := testCLI.NewAlgorithmCmd()
			buf := new(bytes.Buffer)
			cmd.SetOut(buf)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			require.NoError(t, err)

			require.Contains(t, buf.String(), tt.expectedOutput)

			if tt.cleanup != nil {
				tt.cleanup()
			}
		})
	}
}
