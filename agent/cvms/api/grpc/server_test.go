// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/ultravioletrs/cocos/agent/cvms"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

type mockServerStream struct {
	mock.Mock
	cvms.Service_ProcessServer
}

func (m *mockServerStream) Send(msg *cvms.ServerStreamMessage) error {
	args := m.Called(msg)
	return args.Error(0)
}

func (m *mockServerStream) Recv() (*cvms.ClientStreamMessage, error) {
	args := m.Called()
	return args.Get(0).(*cvms.ClientStreamMessage), args.Error(1)
}

func (m *mockServerStream) Context() context.Context {
	args := m.Called()
	return args.Get(0).(context.Context)
}

type mockService struct {
	mock.Mock
}

func (m *mockService) Run(ctx context.Context, ipAddress string, sendMessage SendFunc, authInfo credentials.AuthInfo) {
	m.Called(ctx, ipAddress, sendMessage, authInfo)
}

func TestNewServer(t *testing.T) {
	incoming := make(chan *cvms.ClientStreamMessage)
	mockSvc := new(mockService)

	server := NewServer(incoming, mockSvc)

	assert.NotNil(t, server)
	assert.IsType(t, &grpcServer{}, server)
}

func TestGrpcServer_Process(t *testing.T) {
	tests := []struct {
		name          string
		recvReturn    *cvms.ClientStreamMessage
		recvError     error
		expectedError string
	}{
		{
			name:          "Process with context deadline exceeded",
			recvReturn:    &cvms.ClientStreamMessage{},
			recvError:     nil,
			expectedError: "context deadline exceeded",
		},
		{
			name:          "Process with Recv error",
			recvReturn:    &cvms.ClientStreamMessage{},
			recvError:     errors.New("recv error"),
			expectedError: "recv error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			incoming := make(chan *cvms.ClientStreamMessage, 1)
			mockSvc := new(mockService)
			server := NewServer(incoming, mockSvc).(*grpcServer)

			mockStream := new(mockServerStream)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			mockStream.On("Context").Return(peer.NewContext(ctx, &peer.Peer{
				Addr:     mockAddr{},
				AuthInfo: mockAuthInfo{},
			}))

			if tt.recvError == nil {
				go func() {
					for mes := range incoming {
						assert.NotNil(t, mes)
					}
				}()
			}

			mockStream.On("Recv").Return(tt.recvReturn, tt.recvError)
			mockSvc.On("Run", mock.Anything, "test", mock.Anything, mock.AnythingOfType("mockAuthInfo")).Return()

			err := server.Process(mockStream)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
			mockStream.AssertExpectations(t)
			mockSvc.AssertExpectations(t)
		})
	}
}

func TestGrpcServer_sendRunReqInChunks(t *testing.T) {
	incoming := make(chan *cvms.ClientStreamMessage)
	mockSvc := new(mockService)
	server := NewServer(incoming, mockSvc).(*grpcServer)

	mockStream := new(mockServerStream)

	runReq := &cvms.ComputationRunReq{
		Id: "test-id",
	}

	largePayload := make([]byte, bufferSize*2)
	for i := range largePayload {
		largePayload[i] = byte(i % 256)
	}
	runReq.Algorithm = &cvms.Algorithm{}
	runReq.Algorithm.UserKey = largePayload

	mockStream.On("Send", mock.AnythingOfType("*cvms.ServerStreamMessage")).Return(nil).Times(4)

	err := server.sendRunReqInChunks(mockStream, runReq)

	assert.NoError(t, err)
	mockStream.AssertExpectations(t)

	calls := mockStream.Calls
	assert.Equal(t, 4, len(calls))

	for i, call := range calls {
		msg := call.Arguments[0].(*cvms.ServerStreamMessage)
		chunk := msg.GetRunReqChunks()

		assert.NotNil(t, chunk)
		assert.Equal(t, "test-id", chunk.Id)

		if i < 3 {
			assert.False(t, chunk.IsLast)
		} else {
			assert.Equal(t, 0, len(chunk.Data))
			assert.True(t, chunk.IsLast)
		}
	}
}

type mockAddr struct{}

func (mockAddr) Network() string { return "test network" }
func (mockAddr) String() string  { return "test" }

type mockAuthInfo struct{}

func (mockAuthInfo) AuthType() string { return "test auth" }

func TestGrpcServer_ProcessWithMockService(t *testing.T) {
	tests := []struct {
		name        string
		setupMockFn func(*mockService, *mockServerStream)
	}{
		{
			name: "Run Request Test",
			setupMockFn: func(mockSvc *mockService, mockStream *mockServerStream) {
				mockSvc.On("Run", mock.Anything, "test", mock.Anything, mock.AnythingOfType("mockAuthInfo")).
					Run(func(args mock.Arguments) {
						sendFunc := args.Get(2).(SendFunc)
						runReq := &cvms.ComputationRunReq{Id: "test-run-id"}
						err := sendFunc(&cvms.ServerStreamMessage{
							Message: &cvms.ServerStreamMessage_RunReq{
								RunReq: runReq,
							},
						})
						assert.NoError(t, err)
					}).
					Return()

				mockStream.On("Send", mock.MatchedBy(func(msg *cvms.ServerStreamMessage) bool {
					chunks := msg.GetRunReqChunks()
					return chunks != nil && chunks.Id == "test-run-id"
				})).Return(nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			incoming := make(chan *cvms.ClientStreamMessage, 10)
			mockSvc := new(mockService)
			server := NewServer(incoming, mockSvc).(*grpcServer)

			go func() {
				for mes := range incoming {
					assert.NotNil(t, mes)
				}
			}()

			mockStream := new(mockServerStream)
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()

			peerCtx := peer.NewContext(ctx, &peer.Peer{
				Addr:     mockAddr{},
				AuthInfo: mockAuthInfo{},
			})

			mockStream.On("Context").Return(peerCtx)
			mockStream.On("Recv").Return(&cvms.ClientStreamMessage{}, nil).Maybe()

			tt.setupMockFn(mockSvc, mockStream)

			go func() {
				time.Sleep(150 * time.Millisecond)
				cancel()
			}()

			err := server.Process(mockStream)

			assert.Error(t, err)
			assert.Contains(t, err.Error(), "context canceled")
			mockStream.AssertExpectations(t)
			mockSvc.AssertExpectations(t)
		})
	}
}

func TestGrpcServer_sendRunReqInChunksError(t *testing.T) {
	incoming := make(chan *cvms.ClientStreamMessage)
	mockSvc := new(mockService)
	server := NewServer(incoming, mockSvc).(*grpcServer)

	mockStream := new(mockServerStream)

	runReq := &cvms.ComputationRunReq{
		Id: "test-id",
	}

	// Simulate an error when sending
	mockStream.On("Send", mock.AnythingOfType("*cvms.ServerStreamMessage")).Return(errors.New("send error")).Once()

	err := server.sendRunReqInChunks(mockStream, runReq)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "send error")
	mockStream.AssertExpectations(t)
}

func TestGrpcServer_ProcessMissingPeerInfo(t *testing.T) {
	incoming := make(chan *cvms.ClientStreamMessage)
	mockSvc := new(mockService)
	server := NewServer(incoming, mockSvc).(*grpcServer)

	mockStream := new(mockServerStream)
	ctx := context.Background()

	// Return a context without peer info
	mockStream.On("Context").Return(ctx)

	err := server.Process(mockStream)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get peer info")
	mockStream.AssertExpectations(t)
}
