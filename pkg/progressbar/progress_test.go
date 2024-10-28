// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package progressbar

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/ultravioletrs/cocos/agent"
)

func TestRenderProgressBarWithMockedWidth(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	defer func() {
		w.Close()
		os.Stdout = oldStdout
	}()

	pb := &ProgressBar{
		numberOfBytes:        100,
		currentUploadedBytes: 0,
		TerminalWidthFunc: func() (int, error) {
			return 170, nil
		},
	}

	err := pb.updateProgress(50)
	assert.NoError(t, err)
	err = pb.renderProgressBar()
	assert.NoError(t, err)

	err = w.Close()
	assert.NoError(t, err)

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	assert.NoError(t, err)

	renderedBar := buf.String()
	assert.Contains(t, renderedBar, "[50%]")
}

func TestClearProgressBar(t *testing.T) {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	defer func() {
		w.Close()
		os.Stdout = oldStdout
	}()

	pb := &ProgressBar{
		numberOfBytes:        100,
		currentUploadedBytes: 0,
		maxWidth:             100,
		TerminalWidthFunc: func() (int, error) {
			return 50, nil
		},
	}

	err := pb.updateProgress(50)
	assert.NoError(t, err)
	err = pb.renderProgressBar()
	assert.NoError(t, err)

	err = pb.clearProgressBar()
	assert.NoError(t, err)

	w.Close()

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	assert.NoError(t, err)

	clearedBar := buf.String()
	expectedClear := "\r" + strings.Repeat(" ", pb.maxWidth) + "\r"
	assert.Contains(t, clearedBar, expectedClear)
}

func TestReset(t *testing.T) {
	pb := &ProgressBar{
		numberOfBytes:        100,
		currentUploadedBytes: 7,
		maxWidth:             100,
		description:          "Test Upload",
	}

	description := ""
	totalBytes := 0
	pb.reset(description, totalBytes)

	assert.Equal(t, 0, pb.currentUploadedBytes)
	assert.Equal(t, 0, pb.currentUploadPercentage)
	assert.Equal(t, totalBytes, pb.numberOfBytes)
	assert.Equal(t, description, pb.description)
}

func TestUpdateProgress(t *testing.T) {
	pb := &ProgressBar{
		numberOfBytes:           100,
		currentUploadPercentage: 0,
		currentUploadedBytes:    0,
	}

	bytesRead := 25
	err := pb.updateProgress(bytesRead)
	assert.NoError(t, err)
	assert.Equal(t, 25, pb.currentUploadedBytes)
	assert.Equal(t, 25, pb.currentUploadPercentage)

	bytesRead = 50
	err = pb.updateProgress(bytesRead)
	assert.NoError(t, err)
	assert.Equal(t, 75, pb.currentUploadedBytes)
	assert.Equal(t, 75, pb.currentUploadPercentage)

	bytesRead = 50
	err = pb.updateProgress(bytesRead)
	assert.Error(t, err)
	assert.EqualError(t, err, "progress update exceeds total bytes: attempted to add 50 bytes, but only 25 bytes remain")

	// Ensure the progress does not exceed 100% after the error
	assert.Equal(t, 75, pb.currentUploadedBytes)
	assert.Equal(t, 75, pb.currentUploadPercentage)
}

type MockResultStream struct {
	mock.Mock
	agent.AgentService_ResultClient
}

func (m *MockResultStream) Recv() (*agent.ResultResponse, error) {
	args := m.Called()
	if res := args.Get(0); res != nil {
		return res.(*agent.ResultResponse), args.Error(1)
	}
	return nil, args.Error(1)
}

type MockAttestationStream struct {
	mock.Mock
	agent.AgentService_AttestationClient
}

func (m *MockAttestationStream) Recv() (*agent.AttestationResponse, error) {
	args := m.Called()
	if res := args.Get(0); res != nil {
		return res.(*agent.AttestationResponse), args.Error(1)
	}
	return nil, args.Error(1)
}

func TestReceiveResult(t *testing.T) {
	tests := []struct {
		name        string
		description string
		totalSize   int
		chunks      [][]byte
		setupMock   func(*MockResultStream)
		wantResult  []byte
		wantErr     error
	}{
		{
			name:        "successful single chunk receive",
			description: "Receiving result",
			totalSize:   5,
			chunks:      [][]byte{[]byte("hello")},
			setupMock: func(m *MockResultStream) {
				m.On("Recv").Return(&agent.ResultResponse{File: []byte("hello")}, nil).Once()
				m.On("Recv").Return(nil, io.EOF).Once()
			},
			wantResult: []byte("hello"),
			wantErr:    nil,
		},
		{
			name:        "successful multi-chunk receive",
			description: "Receiving result",
			totalSize:   10,
			chunks:      [][]byte{[]byte("hello"), []byte("world")},
			setupMock: func(m *MockResultStream) {
				m.On("Recv").Return(&agent.ResultResponse{File: []byte("hello")}, nil).Once()
				m.On("Recv").Return(&agent.ResultResponse{File: []byte("world")}, nil).Once()
				m.On("Recv").Return(nil, io.EOF).Once()
			},
			wantResult: []byte("helloworld"),
			wantErr:    nil,
		},
		{
			name:        "stream error",
			description: "Receiving result",
			totalSize:   5,
			setupMock: func(m *MockResultStream) {
				m.On("Recv").Return(nil, errors.New("stream error")).Once()
			},
			wantResult: nil,
			wantErr:    errors.New("stream error"),
		},
		{
			name:        "empty result",
			description: "Receiving result",
			totalSize:   0,
			setupMock: func(m *MockResultStream) {
				m.On("Recv").Return(nil, io.EOF).Once()
			},
			wantResult: nil,
			wantErr:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStream := &MockResultStream{}
			tt.setupMock(mockStream)

			p := New(true)
			// Disable terminal width check for tests
			p.TerminalWidthFunc = func() (int, error) { return 100, nil }

			result, err := p.ReceiveResult(tt.description, tt.totalSize, mockStream)

			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.wantErr.Error(), err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantResult, result)
			}

			mockStream.AssertExpectations(t)
		})
	}
}

func TestReceiveAttestation(t *testing.T) {
	tests := []struct {
		name        string
		description string
		totalSize   int
		chunks      [][]byte
		setupMock   func(*MockAttestationStream)
		wantResult  []byte
		wantErr     error
	}{
		{
			name:        "successful single chunk receive",
			description: "Receiving attestation",
			totalSize:   5,
			chunks:      [][]byte{[]byte("proof")},
			setupMock: func(m *MockAttestationStream) {
				m.On("Recv").Return(&agent.AttestationResponse{File: []byte("proof")}, nil).Once()
				m.On("Recv").Return(nil, io.EOF).Once()
			},
			wantResult: []byte("proof"),
			wantErr:    nil,
		},
		{
			name:        "successful multi-chunk receive",
			description: "Receiving attestation",
			totalSize:   15,
			chunks:      [][]byte{[]byte("proof"), []byte("signature")},
			setupMock: func(m *MockAttestationStream) {
				m.On("Recv").Return(&agent.AttestationResponse{File: []byte("proof")}, nil).Once()
				m.On("Recv").Return(&agent.AttestationResponse{File: []byte("signature")}, nil).Once()
				m.On("Recv").Return(nil, io.EOF).Once()
			},
			wantResult: []byte("proofsignature"),
			wantErr:    nil,
		},
		{
			name:        "stream error",
			description: "Receiving attestation",
			totalSize:   5,
			setupMock: func(m *MockAttestationStream) {
				m.On("Recv").Return(nil, errors.New("attestation error")).Once()
			},
			wantResult: nil,
			wantErr:    errors.New("attestation error"),
		},
		{
			name:        "size mismatch",
			description: "Receiving attestation",
			totalSize:   3,
			chunks:      [][]byte{[]byte("toolong")},
			setupMock: func(m *MockAttestationStream) {
				m.On("Recv").Return(&agent.AttestationResponse{File: []byte("toolong")}, nil).Once()
			},
			wantResult: nil,
			wantErr:    errors.New("progress update exceeds total bytes: attempted to add 7 bytes, but only 3 bytes remain"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStream := &MockAttestationStream{}
			tt.setupMock(mockStream)

			p := New(true)
			// Disable terminal width check for tests
			p.TerminalWidthFunc = func() (int, error) { return 100, nil }

			result, err := p.ReceiveAttestation(tt.description, tt.totalSize, mockStream)

			if tt.wantErr != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.wantErr.Error(), err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantResult, result)
			}

			mockStream.AssertExpectations(t)
		})
	}
}
