// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package events

import (
	"bytes"
	"context"
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
	logger := &slog.Logger{}
	reportBrokenConnection := func(address string) {}
	eventsChan := make(chan *manager.ClientStreamMessage)

	e, err := New(logger, reportBrokenConnection, eventsChan)

	if vsockDeviceExists() {
		assert.NoError(t, err)

		assert.NotNil(t, e)
		assert.IsType(t, &events{}, e)
	} else {
		assert.Error(t, err)
	}
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

	go e.Listen(context.Background())

	time.Sleep(100 * time.Millisecond)

	mockListener.AssertExpectations(t)
}

func TestListenContextDone(t *testing.T) {
	mockListener := new(MockVsockListener)
	mockConn := new(MockConn)

	e := &events{
		lis:    mockListener,
		logger: mglog.NewMock(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	mockListener.On("Accept").Return(mockConn, nil)

	e.Listen(ctx)

	time.Sleep(100 * time.Millisecond)
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
	tests := []struct {
		name    string
		message *manager.ClientStreamMessage
	}{
		{
			name: "handle agent event",
			message: &manager.ClientStreamMessage{
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
			},
		},
		{
			name: "handle agent log",
			message: &manager.ClientStreamMessage{
				Message: &manager.ClientStreamMessage_AgentLog{
					AgentLog: &manager.AgentLog{
						ComputationId: "test_computation",
						Timestamp:     timestamppb.Now(),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockConn := NewMockConnWithBuffer()
			eventsChan := make(chan *manager.ClientStreamMessage, 1)

			e := &events{
				logger:                 mglog.NewMock(),
				eventsChan:             eventsChan,
				reportBrokenConnection: func(address string) {},
			}

			data, err := proto.Marshal(tt.message)
			assert.NoError(t, err)

			messageID := uint32(1)
			err = binary.Write(mockConn.readBuf, binary.LittleEndian, messageID)
			assert.NoError(t, err)
			err = binary.Write(mockConn.readBuf, binary.LittleEndian, uint32(len(data)))
			assert.NoError(t, err)
			_, err = mockConn.readBuf.Write(data)
			assert.NoError(t, err)

			// Add EOF to signal end of stream
			err = binary.Write(mockConn.readBuf, binary.LittleEndian, uint32(0))
			assert.NoError(t, err)
			err = binary.Write(mockConn.readBuf, binary.LittleEndian, uint32(0))
			assert.NoError(t, err)

			done := make(chan struct{})
			go func() {
				e.handleConnection(mockConn)
				close(done)
			}()

			var receivedMessage *manager.ClientStreamMessage
			select {
			case receivedMessage = <-eventsChan:
			case <-time.After(2 * time.Second):
				t.Fatal("Timeout waiting for message in eventsChan")
			}

			assert.NotNil(t, receivedMessage)

			select {
			case <-done:
				// handleConnection has exited
			case <-time.After(2 * time.Second):
				t.Fatal("Timeout waiting for handleConnection to exit")
			}

			// Check if ack was written
			var receivedAck uint32
			err = binary.Read(mockConn.writeBuf, binary.LittleEndian, &receivedAck)
			assert.NoError(t, err)
			assert.Equal(t, messageID, receivedAck)

			// Ensure no unexpected calls were made on the mock
			mockConn.AssertExpectations(t)
		})
	}
}
