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
	"github.com/ultravioletrs/cocos/manager/mocks"
	pkgmanager "github.com/ultravioletrs/cocos/pkg/manager"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type mockStream struct {
	mock.Mock
	grpc.ClientStream
}

func (m *mockStream) Recv() (*pkgmanager.ServerStreamMessage, error) {
	args := m.Called()
	return args.Get(0).(*pkgmanager.ServerStreamMessage), args.Error(1)
}

func (m *mockStream) Send(msg *pkgmanager.ClientStreamMessage) error {
	args := m.Called(msg)
	return args.Error(0)
}

func TestManagerClient_Process(t *testing.T) {
	mockStream := new(mockStream)
	mockSvc := new(mocks.Service)
	messageQueue := make(chan *pkgmanager.ClientStreamMessage, 10)
	logger := mglog.NewMock()

	client := NewClient(mockStream, mockSvc, messageQueue, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	mockStream.On("Recv").Return(&pkgmanager.ServerStreamMessage{Message: &pkgmanager.ServerStreamMessage_StopComputation{StopComputation: &pkgmanager.StopComputation{}}}, nil).Maybe()
	mockStream.On("Send", mock.Anything).Return(nil).Maybe()

	mockSvc.On("Stop", mock.Anything, mock.Anything).Return(nil).Maybe()

	err := client.Process(ctx, cancel)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

func TestManagerClient_handleRunReqChunks(t *testing.T) {
	mockStream := new(mockStream)
	mockSvc := new(mocks.Service)
	messageQueue := make(chan *pkgmanager.ClientStreamMessage, 10)
	logger := mglog.NewMock()

	client := NewClient(mockStream, mockSvc, messageQueue, logger)

	runReq := &pkgmanager.ComputationRunReq{
		Id: "test-id",
	}
	runReqBytes, _ := proto.Marshal(runReq)

	chunk1 := &pkgmanager.ServerStreamMessage_RunReqChunks{
		RunReqChunks: &pkgmanager.RunReqChunks{
			Id:     "chunk-1",
			Data:   runReqBytes[:len(runReqBytes)/2],
			IsLast: false,
		},
	}
	chunk2 := &pkgmanager.ServerStreamMessage_RunReqChunks{
		RunReqChunks: &pkgmanager.RunReqChunks{
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
	runRes, ok := msg.Message.(*pkgmanager.ClientStreamMessage_RunRes)
	assert.True(t, ok)
	assert.Equal(t, "8080", runRes.RunRes.AgentPort)
	assert.Equal(t, "test-id", runRes.RunRes.ComputationId)
}

func TestManagerClient_handleTerminateReq(t *testing.T) {
	client := ManagerClient{}

	terminateReq := &pkgmanager.ServerStreamMessage_TerminateReq{
		TerminateReq: &pkgmanager.Terminate{
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
	messageQueue := make(chan *pkgmanager.ClientStreamMessage, 10)
	logger := mglog.NewMock()

	client := NewClient(mockStream, mockSvc, messageQueue, logger)

	stopReq := &pkgmanager.ServerStreamMessage_StopComputation{
		StopComputation: &pkgmanager.StopComputation{
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
	stopRes, ok := msg.Message.(*pkgmanager.ClientStreamMessage_StopComputationRes)
	assert.True(t, ok)
	assert.Equal(t, "test-comp-id", stopRes.StopComputationRes.ComputationId)
	assert.Empty(t, stopRes.StopComputationRes.Message)
}

func TestManagerClient_handleBackendInfoReq(t *testing.T) {
	mockStream := new(mockStream)
	mockSvc := new(mocks.Service)
	messageQueue := make(chan *pkgmanager.ClientStreamMessage, 10)
	logger := mglog.NewMock()

	client := NewClient(mockStream, mockSvc, messageQueue, logger)

	infoReq := &pkgmanager.ServerStreamMessage_BackendInfoReq{
		BackendInfoReq: &pkgmanager.BackendInfoReq{
			Id: "test-info-id",
		},
	}

	mockSvc.On("FetchBackendInfo").Return([]byte("test-backend-info"), nil)

	client.handleBackendInfoReq(infoReq)

	// Wait for the goroutine to finish
	time.Sleep(50 * time.Millisecond)

	mockSvc.AssertExpectations(t)
	assert.Len(t, messageQueue, 1)

	msg := <-messageQueue
	infoRes, ok := msg.Message.(*pkgmanager.ClientStreamMessage_BackendInfo)
	assert.True(t, ok)
	assert.Equal(t, "test-info-id", infoRes.BackendInfo.Id)
	assert.Equal(t, []byte("test-backend-info"), infoRes.BackendInfo.Info)
}
