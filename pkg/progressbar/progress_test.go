// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package progressbar

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/agent/mocks"
)

func TestNew(t *testing.T) {
	pb := New()
	assert.NotNil(t, pb)
	assert.NotNil(t, pb.TerminalWidthFunc)
}

func TestSendAlgorithm(t *testing.T) {
	pb := New()
	algobuffer := bytes.NewBufferString("algorithm content")
	reqBuffer := bytes.NewBufferString("requirements content")
	algoStream := mocks.NewAgentService_AlgoClient(t)
	algoStream.On("Send", mock.Anything).Return(nil)
	algoStream.On("CloseAndRecv").Return(&agent.AlgoResponse{}, nil)
	mockStream := &mockAlgoStream{stream: algoStream}

	err := pb.SendAlgorithm("Test Algorithm", algobuffer, reqBuffer, &mockStream.stream)
	assert.NoError(t, err)
	algoStream.AssertExpectations(t)
}

func TestSendData(t *testing.T) {
	pb := New()
	buffer := bytes.NewBufferString("test data content")
	dataStream := mocks.NewAgentService_DataClient(t)
	dataStream.On("Send", mock.Anything).Return(nil)
	dataStream.On("CloseAndRecv").Return(&agent.DataResponse{}, nil)
	mockStream := &mockDataStream{stream: dataStream}

	err := pb.SendData("Test Data", "test.txt", buffer, &mockStream.stream)
	assert.NoError(t, err)
}

func TestRenderProgressBarWithDifferentDescriptions(t *testing.T) {
	testCases := []struct {
		description   string
		expectedEmoji string
	}{
		{"Uploading algorithm", "🚀"},
		{"Uploading data", "📦"},
		{"Processing", "🚀"},
	}

	for _, tc := range testCases {
		t.Run(tc.description, func(t *testing.T) {
			pb := &ProgressBar{
				numberOfBytes:        100,
				currentUploadedBytes: 50,
				description:          tc.description,
				TerminalWidthFunc: func() (int, error) {
					return 100, nil
				},
			}

			var buf bytes.Buffer
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			err := pb.renderProgressBar()
			assert.NoError(t, err)

			w.Close()
			os.Stdout = oldStdout

			_, err = io.Copy(&buf, r)
			assert.NoError(t, err)

			renderedBar := buf.String()
			assert.Contains(t, renderedBar, tc.expectedEmoji)
			assert.Contains(t, renderedBar, tc.description)
			assert.Contains(t, renderedBar, "[0%]")
		})
	}
}

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

type mockAlgoStream struct {
	stream             agent.AgentService_AlgoClient
	sendCount          int
	closeAndRecvCalled bool
}

func (m *mockAlgoStream) Send(*agent.AlgoRequest) error {
	m.sendCount++
	return nil
}

func (m *mockAlgoStream) CloseAndRecv() (*agent.AlgoResponse, error) {
	m.closeAndRecvCalled = true
	return &agent.AlgoResponse{}, nil
}

type mockDataStream struct {
	stream             agent.AgentService_DataClient
	sendCount          int
	closeAndRecvCalled bool
}

func (m *mockDataStream) Send(*agent.DataRequest) error {
	m.sendCount++
	return nil
}

func (m *mockDataStream) CloseAndRecv() (*agent.DataResponse, error) {
	m.closeAndRecvCalled = true
	return &agent.DataResponse{}, nil
}
