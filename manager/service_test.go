// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path"
	"testing"

	mglog "github.com/absmach/supermq/logger"
	"github.com/absmach/supermq/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/manager/qemu"
	persistenceMocks "github.com/ultravioletrs/cocos/manager/qemu/mocks"
	"github.com/ultravioletrs/cocos/manager/vm"
	"github.com/ultravioletrs/cocos/manager/vm/mocks"
)

func TestNew(t *testing.T) {
	cfg := qemu.Config{
		HostFwdRange: "6000-6100",
	}
	logger := slog.Default()
	vmf := new(mocks.Provider)

	service, err := New(cfg, "", "", "", logger, vmf.Execute, "", 10)
	require.NoError(t, err)

	assert.NotNil(t, service)
	assert.IsType(t, &managerService{}, service)
}

func TestRun(t *testing.T) {
	vmf := new(mocks.Provider)
	vmMock := new(mocks.VM)
	persistence := new(persistenceMocks.Persistence)
	vmf.On("Execute", mock.Anything, mock.Anything, mock.Anything).Return(vmMock)
	tests := []struct {
		name           string
		binaryBehavior string
		vmStartError   error
		expectedError  error
		ttl            string
	}{
		{
			name:           "Successful run",
			binaryBehavior: "success",
			vmStartError:   nil,
			expectedError:  nil,
			ttl:            "",
		},
		{
			name:           "VM start failure",
			binaryBehavior: "success",
			vmStartError:   assert.AnError,
			expectedError:  assert.AnError,
			ttl:            "",
		},
		{
			name:           "Invalid attestation policy",
			binaryBehavior: "fail",
			vmStartError:   nil,
			expectedError:  ErrFailedToCreateAttestationPolicy,
			ttl:            "",
		},
		{
			name:           "With TTL",
			binaryBehavior: "success",
			vmStartError:   nil,
			expectedError:  nil,
			ttl:            "10s",
		},
		{
			name:           "with exceeded max vms",
			binaryBehavior: "success",
			vmStartError:   nil,
			expectedError:  errors.New("maximum number of VMs exceeded"),
			ttl:            "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.vmStartError == nil {
				vmMock.On("Start").Return(nil).Once()
			} else {
				vmMock.On("Start").Return(tt.vmStartError).Once()
			}

			vmMock.On("SendAgentConfig", mock.Anything).Return(nil)
			vmMock.On("GetProcess").Return(1234)
			vmMock.On("Transition", mock.Anything).Return(nil)

			persistence.On("SaveVM", mock.Anything).Return(nil)

			qemuCfg := qemu.Config{
				EnableSEVSNP: true,
			}
			logger := slog.Default()

			tempDir := CreateDummyAttestationPolicyBinary(t, tt.binaryBehavior)
			defer os.RemoveAll(tempDir)

			ms := &managerService{
				qemuCfg:                     qemuCfg,
				attestationPolicyBinaryPath: path.Join(tempDir, "attestation_policy"),
				pcrValuesFilePath:           tempDir,
				logger:                      logger,
				vms:                         make(map[string]vm.VM),
				vmFactory:                   vmf.Execute,
				persistence:                 persistence,
				ttlManager:                  NewTTLManager(),
			}

			if tt.name == "with exceeded max vms" {
				ms.maxVMs = 1
				ms.vms["existing-vm"] = vmMock // Simulate an existing VM
			}

			ctx := context.Background()

			port, _, err := ms.CreateVM(ctx, &CreateReq{Ttl: tt.ttl})

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Empty(t, port)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, port)
				assert.Len(t, ms.vms, 1)
			}

			vmf.AssertExpectations(t)
		})
	}
}

func TestStop(t *testing.T) {
	vmf := new(mocks.Provider)
	vmMock := new(mocks.VM)
	persistence := new(persistenceMocks.Persistence)
	vmf.On("Execute", mock.Anything, mock.Anything, mock.Anything).Return(vmMock)

	tests := []struct {
		name           string
		computationID  string
		vmStopError    error
		expectedError  error
		initialVMCount int
	}{
		{
			name:           "Successful stop",
			computationID:  "existing-computation",
			vmStopError:    nil,
			expectedError:  nil,
			initialVMCount: 1,
		},
		{
			name:           "Non-existent computation",
			computationID:  "non-existent-computation",
			vmStopError:    nil,
			expectedError:  ErrNotFound,
			initialVMCount: 0,
		},
		{
			name:           "VM stop error",
			computationID:  "error-computation",
			vmStopError:    assert.AnError,
			expectedError:  assert.AnError,
			initialVMCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.Default()
			ms := &managerService{
				logger:      logger,
				vms:         make(map[string]vm.VM),
				persistence: persistence,
				ttlManager:  NewTTLManager(),
			}
			vmMock := new(mocks.VM)

			if tt.vmStopError == nil {
				vmMock.On("Stop").Return(nil).Once()
			} else {
				vmMock.On("Stop").Return(assert.AnError).Once()
			}

			persistence.On("DeleteVM", tt.computationID).Return(nil)

			if tt.initialVMCount > 0 {
				ms.vms[tt.computationID] = vmMock
			}

			err := ms.RemoveVM(context.Background(), tt.computationID)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
				assert.Len(t, ms.vms, 0)
			}
		})
	}
}

func TestGetFreePort(t *testing.T) {
	port, err := getFreePort(6000, 6100)

	assert.NoError(t, err)
	assert.GreaterOrEqual(t, port, 6000)

	_, err = net.Listen("tcp", net.JoinHostPort("localhost", fmt.Sprint(port)))
	assert.NoError(t, err)

	port, err = getFreePort(6000, 6100)
	assert.NoError(t, err)
	assert.Greater(t, port, 6000)
}

func TestDecodeRange(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantStart int
		wantEnd   int
		wantErr   bool
	}{
		{"Valid range", "1-5", 1, 5, false},
		{"Invalid format", "1:5", 0, 0, true},
		{"Start greater than end", "5-1", 0, 0, true},
		{"Non-numeric input", "a-b", 0, 0, true},
		{"Single number", "5", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end, err := decodeRange(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantStart, start)
				assert.Equal(t, tt.wantEnd, end)
			}
		})
	}
}

func TestRestoreVMs(t *testing.T) {
	mockPersistence := new(persistenceMocks.Persistence)
	vmf := new(mocks.Provider)
	vmMock := new(mocks.VM)
	vmf.On("Execute", mock.Anything, mock.Anything, mock.Anything).Return(vmMock)
	vmMock.On("SetProcess", mock.Anything).Return(nil)
	vmMock.On("Transition", mock.Anything).Return(nil)
	ms := &managerService{
		persistence: mockPersistence,
		vms:         make(map[string]vm.VM),
		vmFactory:   vmf.Execute,
		logger:      mglog.NewMock(),
	}

	cmd := exec.Command("echo", "test")
	err := cmd.Start()
	assert.NoError(t, err)

	cmd2 := exec.Command("echo", "test")
	err = cmd2.Run()
	assert.NoError(t, err)

	mockPersistence.On("LoadVMs").Return([]qemu.VMState{
		{ID: "vm1", PID: cmd.Process.Pid},
		{ID: "vm2", PID: cmd2.Process.Pid},
		{ID: "vm3", PID: cmd2.Process.Pid},
	}, nil)

	mockPersistence.On("DeleteVM", "vm2").Return(nil)
	mockPersistence.On("DeleteVM", "vm3").Return(errors.New("failed to delete"))

	err = ms.restoreVMs()
	assert.NoError(t, err)

	assert.Len(t, ms.vms, 1)
	assert.Contains(t, ms.vms, "vm1")

	mockPersistence.AssertExpectations(t)
}

func TestProcessExists(t *testing.T) {
	ms := &managerService{}

	assert.True(t, ms.processExists(os.Getpid()))

	assert.False(t, ms.processExists(99999))

	if os.Getuid() != 0 { // Skip this test if running as root.
		assert.False(t, ms.processExists(1)) // PID 1 is usually the init process.
	}
}

func TestTmpEnvironmentWithAWSCredentials(t *testing.T) {
	tests := []struct {
		name           string
		req            *CreateReq
		wantEnvKeys    []string
		wantEnvNotKeys []string
	}{
		{
			name: "with all AWS credentials",
			req: &CreateReq{
				AgentLogLevel:      "debug",
				AgentCvmServerUrl:  "localhost:7001",
				AwsAccessKeyId:     "AKIAIOSFODNN7EXAMPLE",
				AwsSecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				AwsEndpointUrl:     "http://localhost:9000",
				AwsRegion:          "us-east-1",
			},
			wantEnvKeys:    []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_ENDPOINT_URL", "AWS_REGION"},
			wantEnvNotKeys: []string{},
		},
		{
			name: "with partial AWS credentials",
			req: &CreateReq{
				AgentLogLevel:  "info",
				AwsAccessKeyId: "AKIAIOSFODNN7EXAMPLE",
				AwsRegion:      "eu-west-1",
			},
			wantEnvKeys:    []string{"AWS_ACCESS_KEY_ID", "AWS_REGION"},
			wantEnvNotKeys: []string{"AWS_SECRET_ACCESS_KEY", "AWS_ENDPOINT_URL"},
		},
		{
			name: "without AWS credentials",
			req: &CreateReq{
				AgentLogLevel:     "info",
				AgentCvmServerUrl: "localhost:7001",
			},
			wantEnvKeys:    []string{},
			wantEnvNotKeys: []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_ENDPOINT_URL", "AWS_REGION"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, err := tmpEnvironment("test-id", tt.req)
			require.NoError(t, err)
			defer os.RemoveAll(dir)

			// Read the environment file
			envContent, err := os.ReadFile(path.Join(dir, "environment"))
			require.NoError(t, err)

			envStr := string(envContent)

			for _, key := range tt.wantEnvKeys {
				assert.Contains(t, envStr, key+"=", "expected key %s to be present", key)
			}

			for _, key := range tt.wantEnvNotKeys {
				assert.NotContains(t, envStr, key+"=", "expected key %s to NOT be present", key)
			}
		})
	}
}

func TestShutdown(t *testing.T) {
	ms := &managerService{
		vms:        make(map[string]vm.VM),
		ttlManager: NewTTLManager(),
		logger:     mglog.NewMock(),
	}

	vmMock := new(mocks.VM)
	vmMock.On("Stop").Return(nil).Once()
	ms.vms["test-vm"] = vmMock

	err := ms.Shutdown()
	assert.NoError(t, err)

	assert.Len(t, ms.vms, 0)
}

func TestCreateVMWithAaKbsParams(t *testing.T) {
	vmf := new(mocks.Provider)
	vmMock := new(mocks.VM)
	persistence := new(persistenceMocks.Persistence)

	tests := []struct {
		name              string
		aaKbsParams       string
		expectedKernelArg string
	}{
		{
			name:              "with AaKbsParams",
			aaKbsParams:       "cc_kbc::http://kbs.example.com:8080",
			expectedKernelArg: "agent.aa_kbc_params=cc_kbc::http://kbs.example.com:8080",
		},
		{
			name:              "without AaKbsParams",
			aaKbsParams:       "",
			expectedKernelArg: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedConfig any

			vmf.On("Execute", mock.Anything, mock.Anything, mock.Anything).
				Run(func(args mock.Arguments) {
					capturedConfig = args.Get(0)
				}).
				Return(vmMock).Once()

			vmMock.On("Start").Return(nil).Once()
			vmMock.On("GetProcess").Return(1234).Once()
			vmMock.On("Transition", mock.Anything).Return(nil).Once()
			persistence.On("SaveVM", mock.Anything).Return(nil).Once()

			tempDir := CreateDummyAttestationPolicyBinary(t, "success")
			defer os.RemoveAll(tempDir)

			qemuCfg := qemu.Config{
				EnableSEVSNP:      true,
				KernelCommandLine: "quiet console=null",
			}

			ms := &managerService{
				qemuCfg:                     qemuCfg,
				attestationPolicyBinaryPath: path.Join(tempDir, "attestation_policy"),
				pcrValuesFilePath:           tempDir,
				logger:                      slog.Default(),
				vms:                         make(map[string]vm.VM),
				vmFactory:                   vmf.Execute,
				persistence:                 persistence,
				ttlManager:                  NewTTLManager(),
			}

			ctx := context.Background()

			_, _, err := ms.CreateVM(ctx, &CreateReq{
				AaKbsParams: tt.aaKbsParams,
			})

			require.NoError(t, err)
			require.NotNil(t, capturedConfig)

			vmInfo, ok := capturedConfig.(qemu.VMInfo)
			require.True(t, ok, "expected capturedConfig to be qemu.VMInfo")

			if tt.expectedKernelArg != "" {
				assert.Contains(t, vmInfo.Config.KernelCommandLine, tt.expectedKernelArg)
			} else {
				assert.NotContains(t, vmInfo.Config.KernelCommandLine, "agent.aa_kbc_params=")
			}

			vmf.AssertExpectations(t)
			vmMock.AssertExpectations(t)
		})
	}
}
