// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package events

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"

	mglog "github.com/absmach/magistrala/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/ultravioletrs/cocos/manager"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type MockVsockListener struct {
	mock.Mock
}

func (m *MockVsockListener) Accept() (net.Conn, error) {
	args := m.Called()
	return args.Get(0).(net.Conn), args.Error(1)
}

func (m *MockVsockListener) Close() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockVsockListener) Addr() net.Addr {
	args := m.Called()
	return args.Get(0).(net.Addr)
}

var _ net.Conn = (*MockConn)(nil)

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

func TestNew(t *testing.T) {
	if !vsockDeviceExists() {
		t.Skip("Skipping test: vsock device not available")
	}

	logger := &slog.Logger{}
	reportBrokenConnection := func(address string) {}
	eventsChan := make(chan *manager.ClientStreamMessage)

	e := New(logger, reportBrokenConnection, eventsChan)

	assert.NotNil(t, e)
	assert.IsType(t, &events{}, e)
}

func TestListen(t *testing.T) {
	mockListener := new(MockVsockListener)
	mockConn := new(MockConn)

	e := &events{
		lis:    mockListener,
		logger: mglog.NewMock(),
	}

	mockListener.On("Accept").Return(mockConn, fmt.Errorf("mock error")).Once()
	mockListener.On("Accept").Return(mockConn, nil)
	mockConn.On("Close").Return(nil)
	mockConn.On("Read", mock.Anything).Return(0, nil)

	go e.Listen()

	time.Sleep(100 * time.Millisecond)

	mockListener.AssertExpectations(t)
}

func vsockDeviceExists() bool {
	fs, err := os.Stat("/dev/vsock")
	if err != nil {
		return false
	}
	if fs.Mode()&os.ModeDevice == 0 {
		return false
	}
	return true
}

type MockConnWithBuffer struct {
	mock.Mock
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
}

func NewMockConnWithBuffer() *MockConnWithBuffer {
	return &MockConnWithBuffer{
		readBuf:  new(bytes.Buffer),
		writeBuf: new(bytes.Buffer),
	}
}

func (m *MockConnWithBuffer) Read(b []byte) (n int, err error) {
	return m.readBuf.Read(b)
}

func (m *MockConnWithBuffer) Write(b []byte) (n int, err error) {
	return m.writeBuf.Write(b)
}

func (m *MockConnWithBuffer) Close() error {
	return nil
}

func (m *MockConnWithBuffer) LocalAddr() net.Addr {
	return nil
}

func (m *MockConnWithBuffer) RemoteAddr() net.Addr {
	return &net.IPAddr{IP: net.ParseIP("localhost")}
}

func (m *MockConnWithBuffer) SetDeadline(t time.Time) error {
	return nil
}

func (m *MockConnWithBuffer) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *MockConnWithBuffer) SetWriteDeadline(t time.Time) error {
	return nil
}

func TestHandleConnection(t *testing.T) {
	mockConn := NewMockConnWithBuffer()
	eventsChan := make(chan *manager.ClientStreamMessage, 1)

	e := &events{
		logger:                 mglog.NewMock(),
		eventsChan:             eventsChan,
		reportBrokenConnection: func(address string) {},
	}

	message := &manager.ClientStreamMessage{
		Message: &manager.ClientStreamMessage_AgentEvent{
			AgentEvent: &manager.AgentEvent{
				EventType:     "test_event",
				ComputationId: "test_computation",
				Status:        "test_status",
				Originator:    "test_originator",
				Timestamp:     timestamppb.Now(),
				Details:       []byte("test_details"),
			},
		},
	}

	data, _ := proto.Marshal(message)

	messageID := uint32(1)
	err := binary.Write(mockConn.readBuf, binary.LittleEndian, messageID)
	assert.NoError(t, err)
	err = binary.Write(mockConn.readBuf, binary.LittleEndian, uint32(len(data)))
	assert.NoError(t, err)
	mockConn.readBuf.Write(data)

	err = binary.Write(mockConn.readBuf, binary.LittleEndian, uint32(2))
	assert.NoError(t, err)
	err = binary.Write(mockConn.readBuf, binary.LittleEndian, uint32(0))
	assert.NoError(t, err)

	go e.handleConnection(mockConn)

	time.Sleep(100 * time.Millisecond)

	select {
	case receivedMessage := <-eventsChan:
		assert.NotNil(t, receivedMessage)
	default:
		t.Error("Expected message not received in eventsChan")
	}

	var receivedAck uint32
	err = binary.Read(mockConn.writeBuf, binary.LittleEndian, &receivedAck)
	assert.NoError(t, err)
	assert.Equal(t, messageID, receivedAck)

	time.Sleep(100 * time.Millisecond)

	mockConn.AssertExpectations(t)
}
