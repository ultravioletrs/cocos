// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"
	"testing"
	"time"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/ultravioletrs/cocos/agent/cvm"
	"github.com/ultravioletrs/cocos/agent/cvm/server"
	"github.com/ultravioletrs/cocos/agent/mocks"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type mockStream struct {
	mock.Mock
	grpc.ClientStream
}

func (m *mockStream) Recv() (*cvm.ServerStreamMessage, error) {
	args := m.Called()
	return args.Get(0).(*cvm.ServerStreamMessage), args.Error(1)
}

func (m *mockStream) Send(msg *cvm.ClientStreamMessage) error {
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
				mockStream.On("Recv").Return(&cvm.ServerStreamMessage{
					Message: &cvm.ServerStreamMessage_StopComputation{
						StopComputation: &cvm.StopComputation{},
					},
				}, nil)
				mockStream.On("Send", mock.Anything).Return(nil)
				mockSvc.On("Stop", mock.Anything, mock.Anything).Return(nil)
			},
			expectError: true,
			errorMsg:    "context deadline exceeded",
		},
		{
			name: "Run request chunks",
			setupMocks: func(mockStream *mockStream, mockSvc *mocks.Service) {
				mockStream.On("Recv").Return(&cvm.ServerStreamMessage{
					Message: &cvm.ServerStreamMessage_RunReqChunks{
						RunReqChunks: &cvm.RunReqChunks{},
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
				mockStream.On("Recv").Return(&cvm.ServerStreamMessage{}, assert.AnError)
			},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockStream := new(mockStream)
			mockSvc := new(mocks.Service)
			messageQueue := make(chan *cvm.ClientStreamMessage, 10)
			logger := mglog.NewMock()

			client := NewClient(mockStream, mockSvc, messageQueue, logger, &server.AgentServer{})

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
	messageQueue := make(chan *cvm.ClientStreamMessage, 10)
	logger := mglog.NewMock()

	client := NewClient(mockStream, mockSvc, messageQueue, logger, &server.AgentServer{})

	runReq := &cvm.ComputationRunReq{
		Id: "test-id",
	}
	runReqBytes, _ := proto.Marshal(runReq)

	chunk1 := &cvm.ServerStreamMessage_RunReqChunks{
		RunReqChunks: &cvm.RunReqChunks{
			Id:     "chunk-1",
			Data:   runReqBytes[:len(runReqBytes)/2],
			IsLast: false,
		},
	}
	chunk2 := &cvm.ServerStreamMessage_RunReqChunks{
		RunReqChunks: &cvm.RunReqChunks{
			Id:     "chunk-1",
			Data:   runReqBytes[len(runReqBytes)/2:],
			IsLast: true,
		},
	}

	mockSvc.On("Run", mock.Anything, mock.AnythingOfType("*cvm.ComputationRunReq")).Return("8080", nil)

	err := client.handleRunReqChunks(context.Background(), chunk1)
	assert.NoError(t, err)

	err = client.handleRunReqChunks(context.Background(), chunk2)
	assert.NoError(t, err)

	// Wait for the goroutine to finish
	time.Sleep(50 * time.Millisecond)

	mockSvc.AssertExpectations(t)
	assert.Len(t, messageQueue, 1)

	msg := <-messageQueue
	runRes, ok := msg.Message.(*cvm.ClientStreamMessage_RunRes)
	assert.True(t, ok)
	assert.Equal(t, "test-id", runRes.RunRes.ComputationId)
}

func TestManagerClient_handleStopComputation(t *testing.T) {
	mockStream := new(mockStream)
	mockSvc := new(mocks.Service)
	messageQueue := make(chan *cvm.ClientStreamMessage, 10)
	logger := mglog.NewMock()

	client := NewClient(mockStream, mockSvc, messageQueue, logger, &server.AgentServer{})

	stopReq := &cvm.ServerStreamMessage_StopComputation{
		StopComputation: &cvm.StopComputation{
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
	stopRes, ok := msg.Message.(*cvm.ClientStreamMessage_StopComputationRes)
	assert.True(t, ok)
	assert.Equal(t, "test-comp-id", stopRes.StopComputationRes.ComputationId)
	assert.Empty(t, stopRes.StopComputationRes.Message)
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
