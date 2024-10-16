// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package events

import (
	"fmt"
	"net"
	"testing"
	"time"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/ultravioletrs/cocos/pkg/manager"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestHandleConnection(t *testing.T) {
	ms := &events{
		logger:                 mglog.NewMock(),
		reportBrokenConnection: func(address string) {},
		eventsChan:             make(chan *manager.ClientStreamMessage, 1),
	}

	mockConn := new(MockConn)
	mockAddr := new(MockAddr)
	mockConn.On("RemoteAddr").Return(mockAddr)
	mockConn.On("Close").Return(nil)
	mockAddr.On("String").Return("vm(3)")

	msg := &manager.ClientStreamMessage{
		Message: &manager.ClientStreamMessage_AgentEvent{
			AgentEvent: &manager.AgentEvent{
				EventType:     manager.VmProvision.String(),
				ComputationId: "comp1",
				Status:        manager.VmProvision.String(),
				Timestamp:     timestamppb.Now(),
				Originator:    "agent",
			},
		},
	}
	msgBytes, err := proto.Marshal(msg)
	assert.NoError(t, err)
	fmt.Println(msgBytes)

	mockConn.On("Read", mock.Anything).Return(len(msgBytes), nil).Run(func(args mock.Arguments) {
		copy(args.Get(0).([]byte), msgBytes)
	}).Once()

	mockConn.On("Read", mock.Anything).Return(0, net.ErrClosed)

	go ms.handleConnection(mockConn)

	receivedMsg := <-ms.eventsChan
	assert.Equal(t, msg.GetAgentEvent().EventType, receivedMsg.GetAgentEvent().EventType)
	assert.Equal(t, msg.GetAgentEvent().ComputationId, receivedMsg.GetAgentEvent().ComputationId)
}

type MockConn struct {
	mock.Mock
}

func (m *MockConn) Read(b []byte) (n int, err error) {
	args := m.Called(b)
	return args.Int(0), args.Error(1)
}

func (m *MockConn) Write(b []byte) (n int, err error) {
	args := m.Called(b)
	return args.Int(0), args.Error(1)
}

func (m *MockConn) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockConn) LocalAddr() net.Addr {
	args := m.Called()
	return args.Get(0).(net.Addr)
}

func (m *MockConn) RemoteAddr() net.Addr {
	args := m.Called()
	return args.Get(0).(net.Addr)
}

func (m *MockConn) SetDeadline(t time.Time) error {
	args := m.Called(t)
	return args.Error(0)
}

func (m *MockConn) SetReadDeadline(t time.Time) error {
	args := m.Called(t)
	return args.Error(0)
}

func (m *MockConn) SetWriteDeadline(t time.Time) error {
	args := m.Called(t)
	return args.Error(0)
}

type MockAddr struct {
	mock.Mock
}

func (m *MockAddr) Network() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockAddr) String() string {
	args := m.Called()
	return args.String(0)
}
