// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/manager"
	"github.com/ultravioletrs/cocos/manager/mocks"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestCLI_NewCreateVMCmd(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func(*mocks.ManagerServiceClient)
		setupCLI       func(*CLI)
		setupFiles     func(string) error
		flags          map[string]string
		expectedOutput string
		expectedError  string
		expectError    bool
	}{
		{
			name: "successful VM creation with all flags",
			setupMock: func(m *mocks.ManagerServiceClient) {
				m.On("CreateVm", mock.Anything, mock.MatchedBy(func(req *manager.CreateReq) bool {
					return req.AgentCvmServerUrl == "https://server.com" &&
						req.AgentLogLevel == "debug" &&
						req.AgentCvmCaUrl == "https://ca.com" &&
						req.Ttl == "1h0m0s" &&
						string(req.AgentCvmServerCaCert) == "ca-cert-content" &&
						string(req.AgentCvmClientKey) == "client-key-content" &&
						string(req.AgentCvmClientCert) == "client-cert-content"
				})).Return(&manager.CreateRes{
					CvmId:         "vm-123",
					ForwardedPort: "8080",
				}, nil)
			},
			setupCLI: func(cli *CLI) {
			},
			setupFiles: func(tmpDir string) error {
				files := map[string]string{
					"server-ca.pem":  "ca-cert-content",
					"client-key.pem": "client-key-content",
					"client-crt.pem": "client-cert-content",
				}
				for filename, content := range files {
					if err := os.WriteFile(filepath.Join(tmpDir, filename), []byte(content), 0644); err != nil {
						return err
					}
				}
				return nil
			},
			flags: map[string]string{
				"server-url": "https://server.com",
				"server-ca":  "server-ca.pem",
				"client-key": "client-key.pem",
				"client-crt": "client-crt.pem",
				"ca-url":     "https://ca.com",
				"log-level":  "debug",
				"ttl":        "1h",
			},
			expectedOutput: "✅ Virtual machine created successfully with id vm-123 and port 8080",
			expectError:    false,
		},
		{
			name: "successful VM creation with minimal flags",
			setupMock: func(m *mocks.ManagerServiceClient) {
				m.On("CreateVm", mock.Anything, mock.MatchedBy(func(req *manager.CreateReq) bool {
					return req.AgentCvmServerUrl == "https://server.com" &&
						req.AgentLogLevel == "" &&
						req.AgentCvmCaUrl == "" &&
						req.Ttl == "" &&
						len(req.AgentCvmServerCaCert) == 0 &&
						len(req.AgentCvmClientKey) == 0 &&
						len(req.AgentCvmClientCert) == 0
				})).Return(&manager.CreateRes{
					CvmId:         "vm-456",
					ForwardedPort: "9090",
				}, nil)
			},
			setupCLI: func(cli *CLI) {
			},
			setupFiles: func(tmpDir string) error {
				return nil // No files needed for minimal test
			},
			flags: map[string]string{
				"server-url": "https://server.com",
			},
			expectedOutput: "✅ Virtual machine created successfully with id vm-456 and port 9090",
			expectError:    false,
		},
		{
			name: "manager client initialization failure",
			setupMock: func(m *mocks.ManagerServiceClient) {
				// No expectations set as initialization fails
			},
			setupCLI: func(cli *CLI) {
				cli.connectErr = errors.New("connection failed")
			},
			setupFiles: func(tmpDir string) error {
				return nil
			},
			flags: map[string]string{
				"server-url": "https://server.com",
			},
			expectedError: "Failed to connect to manager: failed to connect to grpc server : failed to exit idle mode: passthrough: received empty target in Build() ❌",
			expectError:   true,
		},
		{
			name: "certificate loading failure",
			setupMock: func(m *mocks.ManagerServiceClient) {
				// No expectations set as cert loading fails
			},
			setupCLI: func(cli *CLI) {
			},
			setupFiles: func(tmpDir string) error {
				return nil // Don't create the cert file
			},
			flags: map[string]string{
				"server-url": "https://server.com",
				"server-ca":  "nonexistent-ca.pem",
			},
			expectedError: "Error loading certs:",
			expectError:   true,
		},
		{
			name: "CreateVm API call failure",
			setupMock: func(m *mocks.ManagerServiceClient) {
				m.On("CreateVm", mock.Anything, mock.Anything).Return(nil, errors.New("API error"))
			},
			setupCLI: func(cli *CLI) {
			},
			setupFiles: func(tmpDir string) error {
				return nil
			},
			flags: map[string]string{
				"server-url": "https://server.com",
			},
			expectedError: "Error creating virtual machine: API error ❌",
			expectError:   true,
		},
		{
			name: "missing required server-url flag",
			setupMock: func(m *mocks.ManagerServiceClient) {
				// No expectations set as command validation fails
			},
			setupCLI: func(cli *CLI) {
			},
			setupFiles: func(tmpDir string) error {
				return nil
			},
			flags:       map[string]string{}, // No server-url flag
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "cli-test-")
			require.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			oldDir, err := os.Getwd()
			require.NoError(t, err)
			err = os.Chdir(tmpDir)
			require.NoError(t, err)
			defer os.Chdir(oldDir)

			err = tt.setupFiles(tmpDir)
			require.NoError(t, err)

			mockClient := new(mocks.ManagerServiceClient)
			tt.setupMock(mockClient)

			mockCLI := &CLI{
				managerClient: mockClient,
			}

			tt.setupCLI(mockCLI)

			cmd := mockCLI.NewCreateVMCmd()

			for flag, value := range tt.flags {
				err := cmd.Flags().Set(flag, value)
				require.NoError(t, err)
			}

			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)

			err = cmd.Execute()

			if tt.expectError {
				if tt.expectedError != "" {
					assert.Contains(t, buf.String(), tt.expectedError)
				}
			} else {
				assert.NoError(t, err)
				if tt.expectedOutput != "" {
					assert.Contains(t, buf.String(), tt.expectedOutput)
				}
			}

			mockClient.AssertExpectations(t)
		})
	}
}

func TestCLI_NewRemoveVMCmd(t *testing.T) {
	tests := []struct {
		name           string
		setupMock      func(*mocks.ManagerServiceClient)
		setupCLI       func(*CLI)
		args           []string
		expectedOutput string
		expectedError  string
		expectError    bool
	}{
		{
			name: "successful VM removal",
			setupMock: func(m *mocks.ManagerServiceClient) {
				m.On("RemoveVm", mock.Anything, &manager.RemoveReq{
					CvmId: "vm-123",
				}).Return(&emptypb.Empty{}, nil)
			},
			setupCLI: func(cli *CLI) {
			},
			args:           []string{"vm-123"},
			expectedOutput: "✅ Virtual machine removed successfully",
			expectError:    false,
		},
		{
			name: "manager client initialization failure",
			setupMock: func(m *mocks.ManagerServiceClient) {
				// No expectations set as initialization fails
			},
			setupCLI: func(cli *CLI) {
				cli.connectErr = errors.New("connection failed")
			},
			args:          []string{"vm-123"},
			expectedError: "Failed to connect to manager: failed to connect to grpc server : failed to exit idle mode: passthrough: received empty target in Build() ❌",
			expectError:   true,
		},
		{
			name: "RemoveVm API call failure",
			setupMock: func(m *mocks.ManagerServiceClient) {
				m.On("RemoveVm", mock.Anything, &manager.RemoveReq{
					CvmId: "vm-456",
				}).Return(nil, errors.New("removal failed"))
			},
			setupCLI: func(cli *CLI) {
			},
			args:          []string{"vm-456"},
			expectedError: "Error removing virtual machine: removal failed ❌",
			expectError:   true,
		},
		{
			name: "missing VM ID argument",
			setupMock: func(m *mocks.ManagerServiceClient) {
				// No expectations set as command validation fails
			},
			setupCLI: func(cli *CLI) {
			},
			args:        []string{}, // No VM ID provided
			expectError: true,
		},
		{
			name: "too many arguments",
			setupMock: func(m *mocks.ManagerServiceClient) {
				// No expectations set as command validation fails
			},
			setupCLI: func(cli *CLI) {
			},
			args:        []string{"vm-123", "extra-arg"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(mocks.ManagerServiceClient)
			tt.setupMock(mockClient)

			mockCLI := &CLI{
				managerClient: mockClient,
			}
			tt.setupCLI(mockCLI)

			cmd := mockCLI.NewRemoveVMCmd()

			cmd.SetArgs(tt.args)

			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)

			err := cmd.Execute()

			if tt.expectError {
				if tt.expectedError != "" {
					assert.Contains(t, buf.String(), tt.expectedError)
				}
			} else {
				assert.NoError(t, err)
				if tt.expectedOutput != "" {
					assert.Contains(t, buf.String(), tt.expectedOutput)
				}
			}

			mockClient.AssertExpectations(t)
		})
	}
}

func TestFileReader(t *testing.T) {
	tests := []struct {
		name           string
		setupFile      func(string) (string, error)
		path           string
		expectedResult []byte
		expectError    bool
	}{
		{
			name: "successful file read",
			setupFile: func(tmpDir string) (string, error) {
				filePath := filepath.Join(tmpDir, "test.txt")
				err := os.WriteFile(filePath, []byte("test content"), 0644)
				return filePath, err
			},
			expectedResult: []byte("test content"),
			expectError:    false,
		},
		{
			name: "empty path returns nil",
			setupFile: func(tmpDir string) (string, error) {
				return "", nil
			},
			path:           "",
			expectedResult: nil,
			expectError:    false,
		},
		{
			name: "nonexistent file returns error",
			setupFile: func(tmpDir string) (string, error) {
				return filepath.Join(tmpDir, "nonexistent.txt"), nil
			},
			expectedResult: nil,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "fileReader-test-")
			require.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			filePath, err := tt.setupFile(tmpDir)
			require.NoError(t, err)

			if tt.path != "" {
				filePath = tt.path
			}

			result, err := fileReader(filePath)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResult, result)
			}
		})
	}
}

func TestLoadCerts(t *testing.T) {
	tests := []struct {
		name        string
		setupFiles  func(string) error
		setupGlobal func(string)
		expectError bool
		validate    func(*testing.T, *manager.CreateReq)
	}{
		{
			name: "successful cert loading with all files",
			setupFiles: func(tmpDir string) error {
				files := map[string]string{
					"client.key": "client-key-content",
					"client.crt": "client-cert-content",
					"server.ca":  "server-ca-content",
				}
				for filename, content := range files {
					if err := os.WriteFile(filepath.Join(tmpDir, filename), []byte(content), 0644); err != nil {
						return err
					}
				}
				return nil
			},
			setupGlobal: func(tmpDir string) {
				agentCVMClientKey = filepath.Join(tmpDir, "client.key")
				agentCVMClientCrt = filepath.Join(tmpDir, "client.crt")
				agentCVMServerCA = filepath.Join(tmpDir, "server.ca")
			},
			expectError: false,
			validate: func(t *testing.T, req *manager.CreateReq) {
				assert.Equal(t, []byte("client-key-content"), req.AgentCvmClientKey)
				assert.Equal(t, []byte("client-cert-content"), req.AgentCvmClientCert)
				assert.Equal(t, []byte("server-ca-content"), req.AgentCvmServerCaCert)
			},
		},
		{
			name: "successful cert loading with empty paths",
			setupFiles: func(tmpDir string) error {
				return nil
			},
			setupGlobal: func(tmpDir string) {
				agentCVMClientKey = ""
				agentCVMClientCrt = ""
				agentCVMServerCA = ""
			},
			expectError: false,
			validate: func(t *testing.T, req *manager.CreateReq) {
				assert.Nil(t, req.AgentCvmClientKey)
				assert.Nil(t, req.AgentCvmClientCert)
				assert.Nil(t, req.AgentCvmServerCaCert)
			},
		},
		{
			name: "client key file read error",
			setupFiles: func(tmpDir string) error {
				return nil // Don't create client key file
			},
			setupGlobal: func(tmpDir string) {
				agentCVMClientKey = filepath.Join(tmpDir, "nonexistent.key")
				agentCVMClientCrt = ""
				agentCVMServerCA = ""
			},
			expectError: true,
		},
		{
			name: "client cert file read error",
			setupFiles: func(tmpDir string) error {
				// Create client key but not cert
				return os.WriteFile(filepath.Join(tmpDir, "client.key"), []byte("key-content"), 0644)
			},
			setupGlobal: func(tmpDir string) {
				agentCVMClientKey = filepath.Join(tmpDir, "client.key")
				agentCVMClientCrt = filepath.Join(tmpDir, "nonexistent.crt")
				agentCVMServerCA = ""
			},
			expectError: true,
		},
		{
			name: "server CA file read error",
			setupFiles: func(tmpDir string) error {
				files := map[string]string{
					"client.key": "client-key-content",
					"client.crt": "client-cert-content",
				}
				for filename, content := range files {
					if err := os.WriteFile(filepath.Join(tmpDir, filename), []byte(content), 0644); err != nil {
						return err
					}
				}
				return nil
			},
			setupGlobal: func(tmpDir string) {
				agentCVMClientKey = filepath.Join(tmpDir, "client.key")
				agentCVMClientCrt = filepath.Join(tmpDir, "client.crt")
				agentCVMServerCA = filepath.Join(tmpDir, "nonexistent.ca")
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "loadCerts-test-")
			require.NoError(t, err)
			defer os.RemoveAll(tmpDir)

			err = tt.setupFiles(tmpDir)
			require.NoError(t, err)

			// Store original global variables
			origClientKey := agentCVMClientKey
			origClientCrt := agentCVMClientCrt
			origServerCA := agentCVMServerCA

			// Setup global variables for test
			tt.setupGlobal(tmpDir)

			// Restore original values after test
			defer func() {
				agentCVMClientKey = origClientKey
				agentCVMClientCrt = origClientCrt
				agentCVMServerCA = origServerCA
			}()

			result, err := loadCerts()

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				if tt.validate != nil {
					tt.validate(t, result)
				}
			}
		})
	}
}

// Test helper functions and edge cases
func TestCommandCreation(t *testing.T) {
	cli := &CLI{}

	t.Run("create-vm command creation", func(t *testing.T) {
		cmd := cli.NewCreateVMCmd()
		assert.NotNil(t, cmd)
		assert.Equal(t, "create-vm", cmd.Use)
		assert.Equal(t, "Create a new virtual machine", cmd.Short)

		// Check that required flags are set
		flag := cmd.Flags().Lookup("server-url")
		assert.NotNil(t, flag)
		// Note: We can't easily test MarkFlagRequired in unit tests
	})

	t.Run("remove-vm command creation", func(t *testing.T) {
		cmd := cli.NewRemoveVMCmd()
		assert.NotNil(t, cmd)
		assert.Equal(t, "remove-vm", cmd.Use)
		assert.Equal(t, "Remove a virtual machine", cmd.Short)
	})
}

func TestTTLHandling(t *testing.T) {
	tests := []struct {
		name        string
		ttlInput    string
		expectedTTL time.Duration
		expectError bool
	}{
		{
			name:        "valid duration",
			ttlInput:    "1h30m",
			expectedTTL: time.Hour + 30*time.Minute,
			expectError: false,
		},
		{
			name:        "zero duration",
			ttlInput:    "0",
			expectedTTL: 0,
			expectError: false,
		},
		{
			name:        "empty string",
			ttlInput:    "",
			expectedTTL: 0,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockCLI := &CLI{
				managerClient: new(mocks.ManagerServiceClient),
			}

			cmd := mockCLI.NewCreateVMCmd()

			if tt.ttlInput != "" {
				err := cmd.Flags().Set("ttl", tt.ttlInput)
				if tt.expectError {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, tt.expectedTTL, ttl)
				}
			}
		})
	}
}
