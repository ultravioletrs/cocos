// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package progressbar

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ultravioletrs/cocos/agent"
	"golang.org/x/term"
)

const (
	progressBarDots = "... "
	leftBracket     = "["
	rightBracket    = "]"
	head            = ">"
	body            = "="
	bodyPadding     = "."
	bufferSize      = 1024 * 1024
)

var (
	_            streamSender = (*algoClientWrapper)(nil)
	_            streamSender = (*dataClientWrapper)(nil)
	warnOnlyOnce              = false
)

type streamSender interface {
	Send(interface{}) error
	CloseAndRecv() (interface{}, error)
}

type algoClientWrapper struct {
	client *agent.AgentService_AlgoClient
}

func (a *algoClientWrapper) Send(req interface{}) error {
	algoReq, ok := req.(*agent.AlgoRequest)
	if !ok {
		return fmt.Errorf("expected *AlgoRequest, got %T", req)
	}

	return (*a.client).Send(algoReq)
}

func (a *algoClientWrapper) CloseAndRecv() (interface{}, error) {
	return (*a.client).CloseAndRecv()
}

type dataClientWrapper struct {
	client *agent.AgentService_DataClient
}

func (a *dataClientWrapper) Send(req interface{}) error {
	dataReq, ok := req.(*agent.DataRequest)
	if !ok {
		return fmt.Errorf("expected *DataRequest, got %T", req)
	}

	return (*a.client).Send(dataReq)
}

func (a *dataClientWrapper) CloseAndRecv() (interface{}, error) {
	return (*a.client).CloseAndRecv()
}

type ProgressBar struct {
	numberOfBytes           int
	currentUploadedBytes    int
	currentUploadPercentage int
	description             string
	maxWidth                int
}

func New() *ProgressBar {
	return &ProgressBar{}
}

func (p *ProgressBar) SendAlgorithm(description string, algobuffer, reqBuffer *bytes.Buffer, stream *agent.AgentService_AlgoClient) error {
	totalSize := algobuffer.Len() + reqBuffer.Len()
	p.reset(description, totalSize)

	wrapper := &algoClientWrapper{client: stream}

	// Send reqBuffer first
	if err := p.sendBuffer(reqBuffer, wrapper, func(data []byte) interface{} {
		return &agent.AlgoRequest{Requirements: data}
	}); err != nil {
		return err
	}

	// Then send algobuffer
	if err := p.sendBuffer(algobuffer, wrapper, func(data []byte) interface{} {
		return &agent.AlgoRequest{Algorithm: data}
	}); err != nil {
		return err
	}

	if _, err := io.WriteString(os.Stdout, "\n"); err != nil {
		return err
	}

	_, err := wrapper.CloseAndRecv()
	return err
}

func (p *ProgressBar) SendData(description string, buffer *bytes.Buffer, stream *agent.AgentService_DataClient) error {
	return p.sendData(description, buffer, &dataClientWrapper{client: stream}, func(data []byte) interface{} {
		return &agent.DataRequest{Dataset: data}
	})
}

func (p *ProgressBar) sendData(description string, buffer *bytes.Buffer, stream streamSender, createRequest func([]byte) interface{}) error {
	p.reset(description, buffer.Len())

	buf := make([]byte, bufferSize)

	for {
		n, err := buffer.Read(buf)
		if err == io.EOF {
			if _, err := io.WriteString(os.Stdout, "\n"); err != nil {
				return err
			}
			break
		}
		if err != nil {
			return err
		}

		p.updateProgress(n)

		if err := stream.Send(createRequest(buf[:n])); err != nil {
			return err
		}

		if err := p.renderProgressBar(); err != nil {
			return err
		}
	}

	_, err := stream.CloseAndRecv()
	return err
}

func (p *ProgressBar) sendBuffer(buffer *bytes.Buffer, stream streamSender, createRequest func([]byte) interface{}) error {
	buf := make([]byte, bufferSize)

	for {
		n, err := buffer.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		p.updateProgress(n)

		if err := stream.Send(createRequest(buf[:n])); err != nil {
			return err
		}

		if err := p.renderProgressBar(); err != nil {
			return err
		}
	}

	return nil
}

func (p *ProgressBar) reset(description string, totalBytes int) {
	p.currentUploadedBytes = 0
	p.currentUploadPercentage = 0
	p.numberOfBytes = totalBytes
	p.description = description
}

func (p *ProgressBar) updateProgress(bytesRead int) {
	if p.currentUploadedBytes < p.numberOfBytes {
		p.currentUploadedBytes += bytesRead
		p.currentUploadPercentage = p.currentUploadedBytes * 100 / p.numberOfBytes
	}
}

// Progress bar example: Uploading algorithm... 25% [==>   ].
func (p *ProgressBar) renderProgressBar() error {
	var builder strings.Builder

	// Get terminal width.
	width, err := terminalWidth()
	if err != nil {
		if !warnOnlyOnce {
			fmt.Println("Progress bar could not be rendered")
			warnOnlyOnce = true
		}
		return nil
	}

	if p.maxWidth < width {
		p.maxWidth = width
	}

	if err := p.clearProgressBar(); err != nil {
		return err
	}

	// The progress bar starts with the description.
	if _, err := builder.WriteString(p.description); err != nil {
		return err
	}

	// Add dots to progress bar.
	if _, err := builder.WriteString(progressBarDots); err != nil {
		return err
	}

	// Add uploaded percentage.
	strCurrentUploadPercentage := fmt.Sprintf("%4d%% ", p.currentUploadPercentage)
	if _, err := builder.WriteString(strCurrentUploadPercentage); err != nil {
		return err
	}

	// Add letf bracket and space to progress bar.
	if _, err := builder.WriteString(leftBracket); err != nil {
		return err
	}

	progressWidth := width - builder.Len() - len(rightBracket+" ")
	numOfCharactersBody := progressWidth * p.currentUploadPercentage / 100
	if numOfCharactersBody == 0 {
		numOfCharactersBody = 1
	}

	numOfCharactersPadding := progressWidth - numOfCharactersBody

	// Add body which represents the percentage.
	progress := strings.Repeat(body, numOfCharactersBody-1)

	// Add progress to the progress bar.
	if _, err := builder.WriteString(progress); err != nil {
		return err
	}

	// Add head to progress bar.
	if _, err := builder.WriteString(head); err != nil {
		return err
	}

	// Add padding to end of bar.
	padding := strings.Repeat(bodyPadding, numOfCharactersPadding)

	// Add padding to progress bar.
	if _, err := builder.WriteString(padding); err != nil {
		return err
	}

	// Add right bracket to progress bar.
	if _, err := builder.WriteString(rightBracket); err != nil {
		return err
	}

	// Write progress bar.
	if _, err := io.WriteString(os.Stdout, builder.String()); err != nil {
		return err
	}

	return nil
}

func terminalWidth() (int, error) {
	width, _, err := term.GetSize(int(os.Stdout.Fd()))
	if err == nil {
		return width, nil
	}

	return 0, err
}

func (p *ProgressBar) clearProgressBar() error {
	emptySpace := fmt.Sprintf("\r%s\r", strings.Repeat(" ", p.maxWidth))
	if _, err := io.WriteString(os.Stdout, emptySpace); err != nil {
		return err
	}

	return nil
}
