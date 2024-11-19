// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"
	"testing"
	"time"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/absmach/magistrala/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/ultravioletrs/cocos/manager"
	"github.com/ultravioletrs/cocos/manager/mocks"
	"github.com/ultravioletrs/cocos/manager/qemu"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type mockStream struct {
	mock.Mock
	grpc.ClientStream
}

func (m *mockStream) Recv() (*manager.ServerStreamMessage, error) {
	args := m.Called()
	return args.Get(0).(*manager.ServerStreamMessage), args.Error(1)
}

func (m *mockStream) Send(msg *manager.ClientStreamMessage) error {
	args := m.Called(msg)
	return args.Error(0)
}

func TestManagerClient_Process1(t *testing.T) {
	tests := []struct {
		name        string
		setupMocks  func(mockStream *mockStream, mockSvc *mocks.Service)
		expectError bool
		errorMsg    string
	}{
		{
			name: "Stop computation",
			setupMocks: func(mockStream *mockStream, mockSvc *mocks.Service) {
				mockStream.On("Recv").Return(&manager.ServerStreamMessage{
					Message: &manager.ServerStreamMessage_StopComputation{
						StopComputation: &manager.StopComputation{},
					},
				}, nil)
				mockStream.On("Send", mock.Anything).Return(nil)
				mockSvc.On("Stop", mock.Anything, mock.Anything).Return(nil)
			},
			expectError: true,
			errorMsg:    "context deadline exceeded",
		},
		{
			name: "Terminate request",
			setupMocks: func(mockStream *mockStream, mockSvc *mocks.Service) {
				mockStream.On("Recv").Return(&manager.ServerStreamMessage{
					Message: &manager.ServerStreamMessage_TerminateReq{
						TerminateReq: &manager.Terminate{},
					},
				}, nil)
			},
			expectError: true,
			errorMsg:    errTerminationFromServer.Error(),
		},
		{
			name: "Attestation Policy request",
			setupMocks: func(mockStream *mockStream, mockSvc *mocks.Service) {
				mockStream.On("Recv").Return(&manager.ServerStreamMessage{
					Message: &manager.ServerStreamMessage_AttestationPolicyReq{
						AttestationPolicyReq: &manager.AttestationPolicyReq{},
					},
				}, nil)
				mockStream.On("Send", mock.Anything).Return(nil).Once()
				mockSvc.On("FetchAttestationPolicy", mock.Anything, mock.Anything).Return(nil, assert.AnError)
			},
			expectError: true,
		},
		{
			name: "Run request chunks",
			setupMocks: func(mockStream *mockStream, mockSvc *mocks.Service) {
				mockStream.On("Recv").Return(&manager.ServerStreamMessage{
					Message: &manager.ServerStreamMessage_RunReqChunks{
						RunReqChunks: &manager.RunReqChunks{},
					},
				}, nil)
				mockStream.On("Send", mock.Anything).Return(nil).Once()
				mockSvc.On("Run", mock.Anything, mock.Anything).Return("", assert.AnError).Once()
			},
			expectError: true,
		},
		{
			name: "Receive error",
			setupMocks: func(mockStream *mockStream, mockSvc *mocks.Service) {
				mockStream.On("Recv").Return(&manager.ServerStreamMessage{}, assert.AnError)
			},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockStream := new(mockStream)
			mockSvc := new(mocks.Service)
			messageQueue := make(chan *manager.ClientStreamMessage, 10)
			logger := mglog.NewMock()

			client := NewClient(mockStream, mockSvc, messageQueue, logger)

			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			tc.setupMocks(mockStream, mockSvc)

			err := client.Process(ctx, cancel)

			if tc.expectError {
				assert.Error(t, err)
				if tc.errorMsg != "" {
					assert.Contains(t, err.Error(), tc.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestManagerClient_handleRunReqChunks(t *testing.T) {
	mockStream := new(mockStream)
	mockSvc := new(mocks.Service)
	messageQueue := make(chan *manager.ClientStreamMessage, 10)
	logger := mglog.NewMock()

	client := NewClient(mockStream, mockSvc, messageQueue, logger)

	runReq := &manager.ComputationRunReq{
		Id: "test-id",
	}
	runReqBytes, _ := proto.Marshal(runReq)

	chunk1 := &manager.ServerStreamMessage_RunReqChunks{
		RunReqChunks: &manager.RunReqChunks{
			Id:     "chunk-1",
			Data:   runReqBytes[:len(runReqBytes)/2],
			IsLast: false,
		},
	}
	chunk2 := &manager.ServerStreamMessage_RunReqChunks{
		RunReqChunks: &manager.RunReqChunks{
			Id:     "chunk-1",
			Data:   runReqBytes[len(runReqBytes)/2:],
			IsLast: true,
		},
	}

	mockSvc.On("Run", mock.Anything, mock.AnythingOfType("*manager.ComputationRunReq")).Return("8080", nil)

	err := client.handleRunReqChunks(context.Background(), chunk1)
	assert.NoError(t, err)

	err = client.handleRunReqChunks(context.Background(), chunk2)
	assert.NoError(t, err)

	// Wait for the goroutine to finish
	time.Sleep(50 * time.Millisecond)

	mockSvc.AssertExpectations(t)
	assert.Len(t, messageQueue, 1)

	msg := <-messageQueue
	runRes, ok := msg.Message.(*manager.ClientStreamMessage_RunRes)
	assert.True(t, ok)
	assert.Equal(t, "8080", runRes.RunRes.AgentPort)
	assert.Equal(t, "test-id", runRes.RunRes.ComputationId)
}

func TestManagerClient_handleTerminateReq(t *testing.T) {
	client := ManagerClient{}

	terminateReq := &manager.ServerStreamMessage_TerminateReq{
		TerminateReq: &manager.Terminate{
			Message: "Test termination",
		},
	}

	err := client.handleTerminateReq(terminateReq)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Test termination")
	assert.True(t, errors.Contains(err, errTerminationFromServer))
}

func TestManagerClient_handleStopComputation(t *testing.T) {
	mockStream := new(mockStream)
	mockSvc := new(mocks.Service)
	messageQueue := make(chan *manager.ClientStreamMessage, 10)
	logger := mglog.NewMock()

	client := NewClient(mockStream, mockSvc, messageQueue, logger)

	stopReq := &manager.ServerStreamMessage_StopComputation{
		StopComputation: &manager.StopComputation{
			ComputationId: "test-comp-id",
		},
	}

	mockSvc.On("Stop", mock.Anything, "test-comp-id").Return(nil)

	client.handleStopComputation(context.Background(), stopReq)

	// Wait for the goroutine to finish
	time.Sleep(50 * time.Millisecond)

	mockSvc.AssertExpectations(t)
	assert.Len(t, messageQueue, 1)

	msg := <-messageQueue
	stopRes, ok := msg.Message.(*manager.ClientStreamMessage_StopComputationRes)
	assert.True(t, ok)
	assert.Equal(t, "test-comp-id", stopRes.StopComputationRes.ComputationId)
	assert.Empty(t, stopRes.StopComputationRes.Message)
}

func TestManagerClient_handleAttestationPolicyReq(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mockStream := new(mockStream)
		mockSvc := new(mocks.Service)
		messageQueue := make(chan *manager.ClientStreamMessage, 10)
		logger := mglog.NewMock()

		client := NewClient(mockStream, mockSvc, messageQueue, logger)

		infoReq := &manager.ServerStreamMessage_AttestationPolicyReq{
			AttestationPolicyReq: &manager.AttestationPolicyReq{
				Id: "test-info-id",
			},
		}

		mockSvc.On("FetchAttestationPolicy", context.Background(), infoReq.AttestationPolicyReq.Id).Return([]byte("test-attestation-policy"), nil)

		client.handleAttestationPolicyReq(context.Background(), infoReq)

		// Wait for the goroutine to finish
		time.Sleep(50 * time.Millisecond)

		mockSvc.AssertExpectations(t)
		assert.Len(t, messageQueue, 1)

		msg := <-messageQueue
		infoRes, ok := msg.Message.(*manager.ClientStreamMessage_AttestationPolicy)
		assert.True(t, ok)
		assert.Equal(t, "test-info-id", infoRes.AttestationPolicy.Id)
		assert.Equal(t, []byte("test-attestation-policy"), infoRes.AttestationPolicy.Info)
	})
	t.Run("error", func(t *testing.T) {
		mockStream := new(mockStream)
		mockSvc := new(mocks.Service)
		messageQueue := make(chan *manager.ClientStreamMessage, 10)
		logger := mglog.NewMock()

		client := NewClient(mockStream, mockSvc, messageQueue, logger)

		infoReq := &manager.ServerStreamMessage_AttestationPolicyReq{
			AttestationPolicyReq: &manager.AttestationPolicyReq{
				Id: "test-info-id",
			},
		}

		mockSvc.On("FetchAttestationPolicy", context.Background(), infoReq.AttestationPolicyReq.Id).Return(nil, assert.AnError)

		client.handleAttestationPolicyReq(context.Background(), infoReq)

		time.Sleep(50 * time.Millisecond)

		mockSvc.AssertExpectations(t)
		assert.Len(t, messageQueue, 0)
	})
}

func TestManagerClient_handleSVMInfoReq(t *testing.T) {
	mockStream := new(mockStream)
	mockSvc := new(mocks.Service)
	messageQueue := make(chan *manager.ClientStreamMessage, 10)
	logger := mglog.NewMock()

	client := NewClient(mockStream, mockSvc, messageQueue, logger)

	mockSvc.On("ReturnSVMInfo", context.Background()).Return("edk2-stable202408", 4, "EPYC", "")

	client.handleSVMInfoReq(context.Background(), &manager.ServerStreamMessage_SvmInfoReq{SvmInfoReq: &manager.SVMInfoReq{Id: "test-svm-info-id"}})

	// Wait for the goroutine to finish
	time.Sleep(50 * time.Millisecond)

	mockSvc.AssertExpectations(t)
	assert.Len(t, messageQueue, 1)

	msg := <-messageQueue
	infoRes, ok := msg.Message.(*manager.ClientStreamMessage_SvmInfo)
	assert.True(t, ok)
	assert.Equal(t, "edk2-stable202408", infoRes.SvmInfo.OvmfVersion)
	assert.Equal(t, int32(4), infoRes.SvmInfo.CpuNum)
	assert.Equal(t, "EPYC", infoRes.SvmInfo.CpuType)
	assert.Equal(t, "", infoRes.SvmInfo.EosVersion)
	assert.Equal(t, qemu.KernelCommandLine, infoRes.SvmInfo.KernelCmd)
}

func TestManagerClient_timeoutRequest(t *testing.T) {
	rm := newRunRequestManager()
	rm.requests["test-id"] = &runRequest{
		timer:     time.NewTimer(100 * time.Millisecond),
		buffer:    []byte("test-data"),
		lastChunk: time.Now(),
	}

	rm.timeoutRequest("test-id")

	assert.Len(t, rm.requests, 0)
}
