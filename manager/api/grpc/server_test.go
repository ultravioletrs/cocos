// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/ultravioletrs/cocos/manager"
	"github.com/ultravioletrs/cocos/manager/mocks"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestNewServer(t *testing.T) {
	mockSvc := new(mocks.Service)
	server := NewServer(mockSvc)

	assert.NotNil(t, server)
	assert.IsType(t, &grpcServer{}, server)

	grpcSrv := server.(*grpcServer)
	assert.Equal(t, mockSvc, grpcSrv.svc)
}

func TestCreateVm(t *testing.T) {
	tests := []struct {
		name        string
		req         *manager.CreateReq
		mockPort    string
		mockId      string
		mockErr     error
		expectedRes *manager.CreateRes
		expectedErr error
	}{
		{
			name:     "successful VM creation",
			req:      &manager.CreateReq{},
			mockPort: "8080",
			mockId:   "vm-123",
			mockErr:  nil,
			expectedRes: &manager.CreateRes{
				ForwardedPort: "8080",
				CvmId:         "vm-123",
			},
			expectedErr: nil,
		},
		{
			name:     "VM creation with different port",
			req:      &manager.CreateReq{},
			mockPort: "9090",
			mockId:   "vm-456",
			mockErr:  nil,
			expectedRes: &manager.CreateRes{
				ForwardedPort: "9090",
				CvmId:         "vm-456",
			},
			expectedErr: nil,
		},
		{
			name:        "VM creation failure",
			req:         &manager.CreateReq{},
			mockPort:    "",
			mockId:      "",
			mockErr:     errors.New("failed to create VM"),
			expectedRes: nil,
			expectedErr: errors.New("failed to create VM"),
		},
		{
			name:     "VM creation with empty request",
			req:      &manager.CreateReq{},
			mockPort: "3000",
			mockId:   "vm-empty",
			mockErr:  nil,
			expectedRes: &manager.CreateRes{
				ForwardedPort: "3000",
				CvmId:         "vm-empty",
			},
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := new(mocks.Service)
			server := NewServer(mockSvc)

			mockSvc.On("CreateVM", mock.Anything, tt.req).Return(tt.mockPort, tt.mockId, tt.mockErr)

			res, err := server.CreateVm(context.Background(), tt.req)

			if tt.expectedErr != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedErr.Error(), err.Error())
				assert.Nil(t, res)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedRes, res)
			}

			mockSvc.AssertExpectations(t)
		})
	}
}

func TestRemoveVm(t *testing.T) {
	tests := []struct {
		name        string
		req         *manager.RemoveReq
		mockErr     error
		expectedErr error
	}{
		{
			name: "successful VM removal",
			req: &manager.RemoveReq{
				CvmId: "vm-123",
			},
			mockErr:     nil,
			expectedErr: nil,
		},
		{
			name: "VM removal failure",
			req: &manager.RemoveReq{
				CvmId: "vm-456",
			},
			mockErr:     errors.New("VM not found"),
			expectedErr: errors.New("VM not found"),
		},
		{
			name: "VM removal with empty ID",
			req: &manager.RemoveReq{
				CvmId: "",
			},
			mockErr:     errors.New("invalid VM ID"),
			expectedErr: errors.New("invalid VM ID"),
		},
		{
			name: "VM removal with non-existent ID",
			req: &manager.RemoveReq{
				CvmId: "non-existent-vm",
			},
			mockErr:     errors.New("VM does not exist"),
			expectedErr: errors.New("VM does not exist"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := new(mocks.Service)
			server := NewServer(mockSvc)

			mockSvc.On("RemoveVM", mock.Anything, tt.req.CvmId).Return(tt.mockErr)

			res, err := server.RemoveVm(context.Background(), tt.req)

			if tt.expectedErr != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedErr.Error(), err.Error())
				assert.Nil(t, res)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, &emptypb.Empty{}, res)
			}

			mockSvc.AssertExpectations(t)
		})
	}
}

func TestCVMInfo(t *testing.T) {
	tests := []struct {
		name           string
		req            *manager.CVMInfoReq
		mockOvmf       string
		mockCpuNum     int
		mockCpuType    string
		mockEosVersion string
		expectedRes    *manager.CVMInfoRes
	}{
		{
			name: "successful CVM info retrieval",
			req: &manager.CVMInfoReq{
				Id: "cvm-123",
			},
			mockOvmf:       "OVMF-v1.0",
			mockCpuNum:     4,
			mockCpuType:    "Intel-x86_64",
			mockEosVersion: "EOS-v2.1",
			expectedRes: &manager.CVMInfoRes{
				OvmfVersion: "OVMF-v1.0",
				CpuNum:      4,
				CpuType:     "Intel-x86_64",
				EosVersion:  "EOS-v2.1",
				Id:          "cvm-123",
			},
		},
		{
			name: "CVM info with different values",
			req: &manager.CVMInfoReq{
				Id: "cvm-456",
			},
			mockOvmf:       "OVMF-v2.0",
			mockCpuNum:     8,
			mockCpuType:    "AMD-x86_64",
			mockEosVersion: "EOS-v3.0",
			expectedRes: &manager.CVMInfoRes{
				OvmfVersion: "OVMF-v2.0",
				CpuNum:      8,
				CpuType:     "AMD-x86_64",
				EosVersion:  "EOS-v3.0",
				Id:          "cvm-456",
			},
		},
		{
			name: "CVM info with empty ID",
			req: &manager.CVMInfoReq{
				Id: "",
			},
			mockOvmf:       "OVMF-v1.5",
			mockCpuNum:     2,
			mockCpuType:    "ARM64",
			mockEosVersion: "EOS-v1.8",
			expectedRes: &manager.CVMInfoRes{
				OvmfVersion: "OVMF-v1.5",
				CpuNum:      2,
				CpuType:     "ARM64",
				EosVersion:  "EOS-v1.8",
				Id:          "",
			},
		},
		{
			name: "CVM info with zero CPU count",
			req: &manager.CVMInfoReq{
				Id: "cvm-zero",
			},
			mockOvmf:       "OVMF-v1.0",
			mockCpuNum:     0,
			mockCpuType:    "Unknown",
			mockEosVersion: "EOS-v1.0",
			expectedRes: &manager.CVMInfoRes{
				OvmfVersion: "OVMF-v1.0",
				CpuNum:      0,
				CpuType:     "Unknown",
				EosVersion:  "EOS-v1.0",
				Id:          "cvm-zero",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := new(mocks.Service)
			server := NewServer(mockSvc)

			mockSvc.On("ReturnCVMInfo", mock.Anything).Return(
				tt.mockOvmf, tt.mockCpuNum, tt.mockCpuType, tt.mockEosVersion)

			res, err := server.CVMInfo(context.Background(), tt.req)

			assert.NoError(t, err)
			assert.Equal(t, tt.expectedRes, res)

			mockSvc.AssertExpectations(t)
		})
	}
}

func TestAttestationPolicy(t *testing.T) {
	tests := []struct {
		name        string
		req         *manager.AttestationPolicyReq
		mockPolicy  string
		mockErr     error
		expectedRes *manager.AttestationPolicyRes
		expectedErr error
	}{
		{
			name: "successful attestation policy fetch",
			req: &manager.AttestationPolicyReq{
				Id: "policy-123",
			},
			mockPolicy: `{"version": "1.0", "rules": ["rule1", "rule2"]}`,
			mockErr:    nil,
			expectedRes: &manager.AttestationPolicyRes{
				Info: []byte(`{"version": "1.0", "rules": ["rule1", "rule2"]}`),
				Id:   "policy-123",
			},
			expectedErr: nil,
		},
		{
			name: "attestation policy fetch failure",
			req: &manager.AttestationPolicyReq{
				Id: "policy-456",
			},
			mockPolicy:  "",
			mockErr:     errors.New("policy not found"),
			expectedRes: nil,
			expectedErr: errors.New("policy not found"),
		},
		{
			name: "attestation policy with empty ID",
			req: &manager.AttestationPolicyReq{
				Id: "",
			},
			mockPolicy:  "",
			mockErr:     errors.New("invalid policy ID"),
			expectedRes: nil,
			expectedErr: errors.New("invalid policy ID"),
		},
		{
			name: "attestation policy with different content",
			req: &manager.AttestationPolicyReq{
				Id: "policy-789",
			},
			mockPolicy: `{"version": "2.0", "attestation_type": "SGX"}`,
			mockErr:    nil,
			expectedRes: &manager.AttestationPolicyRes{
				Info: []byte(`{"version": "2.0", "attestation_type": "SGX"}`),
				Id:   "policy-789",
			},
			expectedErr: nil,
		},
		{
			name: "attestation policy with empty policy content",
			req: &manager.AttestationPolicyReq{
				Id: "policy-empty",
			},
			mockPolicy: "",
			mockErr:    nil,
			expectedRes: &manager.AttestationPolicyRes{
				Info: []byte{},
				Id:   "policy-empty",
			},
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockSvc := new(mocks.Service)
			server := NewServer(mockSvc)

			mockSvc.On("FetchAttestationPolicy", mock.Anything, tt.req.Id).Return([]byte(tt.mockPolicy), tt.mockErr)

			res, err := server.AttestationPolicy(context.Background(), tt.req)

			if tt.expectedErr != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedErr.Error(), err.Error())
				assert.Nil(t, res)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedRes, res)
			}

			mockSvc.AssertExpectations(t)
		})
	}
}

func TestContextCancellation(t *testing.T) {
	t.Run("CreateVm with cancelled context", func(t *testing.T) {
		mockSvc := new(mocks.Service)
		server := NewServer(mockSvc)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel the context immediately

		req := &manager.CreateReq{}
		mockSvc.On("CreateVM", mock.Anything, req).Return("", "", context.Canceled)

		res, err := server.CreateVm(ctx, req)

		assert.Error(t, err)
		assert.Equal(t, context.Canceled, err)
		assert.Nil(t, res)

		mockSvc.AssertExpectations(t)
	})

	t.Run("RemoveVm with cancelled context", func(t *testing.T) {
		mockSvc := new(mocks.Service)
		server := NewServer(mockSvc)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel the context immediately

		req := &manager.RemoveReq{CvmId: "vm-123"}
		mockSvc.On("RemoveVM", mock.Anything, "vm-123").Return(context.Canceled)

		res, err := server.RemoveVm(ctx, req)

		assert.Error(t, err)
		assert.Equal(t, context.Canceled, err)
		assert.Nil(t, res)

		mockSvc.AssertExpectations(t)
	})
}

func TestErrorHandling(t *testing.T) {
	t.Run("service returns multiple error types", func(t *testing.T) {
		mockSvc := new(mocks.Service)
		server := NewServer(mockSvc)

		// Test with different error types
		customErr := errors.New("custom service error")

		req := &manager.CreateReq{}
		mockSvc.On("CreateVM", mock.Anything, req).Return("", "", customErr)

		res, err := server.CreateVm(context.Background(), req)

		assert.Error(t, err)
		assert.Equal(t, customErr, err)
		assert.Nil(t, res)

		mockSvc.AssertExpectations(t)
	})
}
