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
	"github.com/ultravioletrs/cocos/agent/cvms"
	servermocks "github.com/ultravioletrs/cocos/agent/cvms/server/mocks"
	"github.com/ultravioletrs/cocos/agent/mocks"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type mockStream struct {
	mock.Mock
	grpc.ClientStream
}

func (m *mockStream) Recv() (*cvms.ServerStreamMessage, error) {
	args := m.Called()
	return args.Get(0).(*cvms.ServerStreamMessage), args.Error(1)
}

func (m *mockStream) Send(msg *cvms.ClientStreamMessage) error {
	args := m.Called(msg)
	return args.Error(0)
}

func TestManagerClient_Process(t *testing.T) {
	tests := []struct {
		name        string
		setupMocks  func(mockStream *mockStream, mockSvc *mocks.Service, mockServerSvc *servermocks.AgentServer)
		expectError bool
		errorMsg    string
	}{
		{
			name: "Stop computation",
			setupMocks: func(mockStream *mockStream, mockSvc *mocks.Service, mockServerSvc *servermocks.AgentServer) {
				mockStream.On("Recv").Return(&cvms.ServerStreamMessage{
					Message: &cvms.ServerStreamMessage_StopComputation{
						StopComputation: &cvms.StopComputation{},
					},
				}, nil)
				mockStream.On("Send", mock.Anything).Return(nil)
				mockSvc.On("StopComputation", mock.Anything).Return(nil)
				mockServerSvc.On("Stop").Return(nil)
			},
			expectError: true,
			errorMsg:    "context deadline exceeded",
		},
		{
			name: "Run request chunks",
			setupMocks: func(mockStream *mockStream, mockSvc *mocks.Service, mockServerSvc *servermocks.AgentServer) {
				mockStream.On("Recv").Return(&cvms.ServerStreamMessage{
					Message: &cvms.ServerStreamMessage_RunReqChunks{
						RunReqChunks: &cvms.RunReqChunks{},
					},
				}, nil)
				mockStream.On("Send", mock.Anything).Return(nil).Once()
				mockSvc.On("Run", mock.Anything, mock.Anything).Return("", assert.AnError).Once()
			},
			expectError: true,
		},
		{
			name: "Receive error",
			setupMocks: func(mockStream *mockStream, mockSvc *mocks.Service, mockServerSvc *servermocks.AgentServer) {
				mockStream.On("Recv").Return(&cvms.ServerStreamMessage{}, assert.AnError)
			},
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockStream := new(mockStream)
			mockSvc := new(mocks.Service)
			mockServerSvc := new(servermocks.AgentServer)
			messageQueue := make(chan *cvms.ClientStreamMessage, 100)
			logger := mglog.NewMock()

			client, err := NewClient(mockStream, mockSvc, messageQueue, logger, mockServerSvc, t.TempDir(), func(ctx context.Context) (cvms.Service_ProcessClient, error) { return nil, nil })
			assert.NoError(t, err)

			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			tc.setupMocks(mockStream, mockSvc, mockServerSvc)

			err = client.Process(ctx, cancel)

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
	mockServerSvc := new(servermocks.AgentServer)
	messageQueue := make(chan *cvms.ClientStreamMessage, 10)
	logger := mglog.NewMock()

	client, err := NewClient(mockStream, mockSvc, messageQueue, logger, mockServerSvc, t.TempDir(), func(ctx context.Context) (cvms.Service_ProcessClient, error) { return nil, nil })
	assert.NoError(t, err)

	runReq := &cvms.ComputationRunReq{
		Id: "test-id",
	}
	runReqBytes, _ := proto.Marshal(runReq)

	chunk1 := &cvms.ServerStreamMessage_RunReqChunks{
		RunReqChunks: &cvms.RunReqChunks{
			Id:     "chunk-1",
			Data:   runReqBytes[:len(runReqBytes)/2],
			IsLast: false,
		},
	}
	chunk2 := &cvms.ServerStreamMessage_RunReqChunks{
		RunReqChunks: &cvms.RunReqChunks{
			Id:     "chunk-1",
			Data:   runReqBytes[len(runReqBytes)/2:],
			IsLast: true,
		},
	}

	mockSvc.On("InitComputation", mock.Anything, mock.Anything).Return(nil)
	mockServerSvc.On("Start", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	err = client.handleRunReqChunks(context.Background(), chunk1)
	assert.NoError(t, err)

	err = client.handleRunReqChunks(context.Background(), chunk2)
	assert.NoError(t, err)

	// Wait for the goroutine to finish
	time.Sleep(50 * time.Millisecond)

	mockSvc.AssertExpectations(t)
	assert.Len(t, messageQueue, 1)

	msg := <-messageQueue
	runRes, ok := msg.Message.(*cvms.ClientStreamMessage_RunRes)
	assert.True(t, ok)
	assert.Equal(t, "test-id", runRes.RunRes.ComputationId)
}

func TestManagerClient_handleStopComputation(t *testing.T) {
	mockStream := new(mockStream)
	mockSvc := new(mocks.Service)
	mockServerSvc := new(servermocks.AgentServer)
	messageQueue := make(chan *cvms.ClientStreamMessage, 10)
	logger := mglog.NewMock()

	client, err := NewClient(mockStream, mockSvc, messageQueue, logger, mockServerSvc, t.TempDir(), func(ctx context.Context) (cvms.Service_ProcessClient, error) { return nil, nil })
	assert.NoError(t, err)

	stopReq := &cvms.ServerStreamMessage_StopComputation{
		StopComputation: &cvms.StopComputation{
			ComputationId: "test-comp-id",
		},
	}

	mockSvc.On("StopComputation", mock.Anything).Return(nil)
	mockServerSvc.On("Stop").Return(nil)

	client.handleStopComputation(context.Background(), stopReq)

	// Wait for the goroutine to finish
	time.Sleep(50 * time.Millisecond)

	mockSvc.AssertExpectations(t)
	assert.Len(t, messageQueue, 1)

	msg := <-messageQueue
	stopRes, ok := msg.Message.(*cvms.ClientStreamMessage_StopComputationRes)
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
