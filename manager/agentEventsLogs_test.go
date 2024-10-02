// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"net"
	"testing"
	"time"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/ultravioletrs/cocos/manager/qemu"
	"github.com/ultravioletrs/cocos/manager/vm"
	"github.com/ultravioletrs/cocos/pkg/manager"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

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

func TestComputationIDFromAddress(t *testing.T) {
	ms := &managerService{
		vms: map[string]vm.VM{
			"comp1": qemu.NewVM(qemu.Config{VSockConfig: qemu.VSockConfig{GuestCID: 3}}, make(chan *manager.ClientStreamMessage), "comp1"),
			"comp2": qemu.NewVM(qemu.Config{VSockConfig: qemu.VSockConfig{GuestCID: 5}}, make(chan *manager.ClientStreamMessage), "comp2"),
		},
	}

	tests := []struct {
		name    string
		address string
		want    string
		wantErr bool
	}{
		{"Valid address", "vm(3)", "comp1", false},
		{"Invalid address", "invalid", "", true},
		{"Non-existent CID", "vm(10)", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ms.computationIDFromAddress(tt.address)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestHandleConnection(t *testing.T) {
	ms := &managerService{
		vms: map[string]vm.VM{
			"comp1": qemu.NewVM(qemu.Config{VSockConfig: qemu.VSockConfig{GuestCID: 3}}, make(chan *manager.ClientStreamMessage), "comp1"),
		},
		eventsChan: make(chan *manager.ClientStreamMessage, 1),
		logger:     mglog.NewMock(),
	}

	mockConn := new(MockConn)
	mockAddr := new(MockAddr)
	mockConn.On("RemoteAddr").Return(mockAddr)
	mockConn.On("Close").Return(nil)
	mockAddr.On("String").Return("vm(3)")

	msg := &manager.ClientStreamMessage{
		Message: &manager.ClientStreamMessage_AgentEvent{
			AgentEvent: &manager.AgentEvent{
				EventType:     manager.VmRunning.String(),
				ComputationId: "comp1",
				Status:        manager.VmRunning.String(),
				Timestamp:     timestamppb.Now(),
				Originator:    "agent",
			},
		},
	}
	msgBytes, _ := proto.Marshal(msg)

	mockConn.On("Read", mock.Anything).Return(len(msgBytes), nil).Run(func(args mock.Arguments) {
		copy(args.Get(0).([]byte), msgBytes)
	}).Once()

	mockConn.On("Read", mock.Anything).Return(0, net.ErrClosed)

	go ms.handleConnection(mockConn)

	receivedMsg := <-ms.eventsChan
	assert.Equal(t, msg.GetAgentEvent().EventType, receivedMsg.GetAgentEvent().EventType)
	assert.Equal(t, msg.GetAgentEvent().ComputationId, receivedMsg.GetAgentEvent().ComputationId)

	mockConn.AssertExpectations(t)
}

func TestReportBrokenConnection(t *testing.T) {
	ms := &managerService{
		eventsChan: make(chan *manager.ClientStreamMessage, 1),
	}

	ms.reportBrokenConnection("comp1")

	select {
	case msg := <-ms.eventsChan:
		assert.Equal(t, "comp1", msg.GetAgentEvent().ComputationId)
		assert.Equal(t, manager.Disconnected.String(), msg.GetAgentEvent().Status)
		assert.Equal(t, "manager", msg.GetAgentEvent().Originator)
	default:
		t.Error("Expected message in eventsChan, but none received")
	}
}
