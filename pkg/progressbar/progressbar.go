// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package progressbar

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"golang.org/x/term"
)

const (
	leftBracket  = "["
	rightBracket = "]"
	bufferSize   = 1024 * 1024
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
	client agent.AgentService_AlgoClient
}

func (a *algoClientWrapper) Send(req interface{}) error {
	algoReq, ok := req.(*agent.AlgoRequest)
	if !ok {
		return fmt.Errorf("expected *AlgoRequest, got %T", req)
	}

	return a.client.Send(algoReq)
}

func (a *algoClientWrapper) CloseAndRecv() (interface{}, error) {
	return a.client.CloseAndRecv()
}

type dataClientWrapper struct {
	client agent.AgentService_DataClient
}

func (a *dataClientWrapper) Send(req interface{}) error {
	dataReq, ok := req.(*agent.DataRequest)
	if !ok {
		return fmt.Errorf("expected *DataRequest, got %T", req)
	}

	return a.client.Send(dataReq)
}

func (a *dataClientWrapper) CloseAndRecv() (interface{}, error) {
	return a.client.CloseAndRecv()
}

type ProgressBar struct {
	numberOfBytes           int
	currentUploadedBytes    int
	currentUploadPercentage int
	description             string
	maxWidth                int
	TerminalWidthFunc       func() (int, error)
	isDownload              bool
}

func New(isDownload bool) *ProgressBar {
	return &ProgressBar{
		TerminalWidthFunc: terminalWidth,
		isDownload:        isDownload,
	}
}

func (p *ProgressBar) SendAlgorithm(description string, algo, req *os.File, stream agent.AgentService_AlgoClient) error {
	algoFileInfo, err := algo.Stat()
	if err != nil {
		return err
	}

	reqSize := 0
	if req != nil {
		reqFileInfo, err := req.Stat()
		if err != nil {
			return err
		}
		reqSize = int(reqFileInfo.Size())
	}

	totalSize := int(algoFileInfo.Size()) + reqSize
	p.reset(description, totalSize)

	wrapper := &algoClientWrapper{client: stream}

	// Send req first
	if req != nil {
		if err := p.sendBuffer(req, wrapper, func(data []byte) interface{} {
			return &agent.AlgoRequest{Requirements: data}
		}); err != nil {
			return err
		}
	}

	// Then send algo
	if err := p.sendBuffer(algo, wrapper, func(data []byte) interface{} {
		return &agent.AlgoRequest{Algorithm: data}
	}); err != nil {
		return err
	}

	if _, err := io.WriteString(os.Stdout, "\n"); err != nil {
		return err
	}

	_, err = wrapper.CloseAndRecv()
	if err != nil {
		return err
	}

	return nil
}

func (p *ProgressBar) SendData(description, filename string, file *os.File, stream agent.AgentService_DataClient) error {
	return p.sendData(description, file, &dataClientWrapper{client: stream}, func(data []byte) interface{} {
		if len(data) == 0 {
			fmt.Println("No data to send, skipping...")
		}
		return &agent.DataRequest{Dataset: data, Filename: filename}
	})
}

func (p *ProgressBar) sendData(description string, file *os.File, stream streamSender, createRequest func([]byte) interface{}) error {
	dataInfo, err := file.Stat()
	if err != nil {
		return err
	}

	fmt.Println("Uploading data:", dataInfo.Name(), "(", dataInfo.Size(), "bytes )")

	p.reset(description, int(dataInfo.Size()))

	buf := make([]byte, bufferSize)

	for {
		n, err := file.Read(buf)
		if err == io.EOF {
			if _, err := io.WriteString(os.Stdout, "\n"); err != nil {
				return err
			}
			break
		}
		if err != nil {
			return err
		}

		err = p.updateProgress(n)
		if err != nil {
			return err
		}

		if err := stream.Send(createRequest(buf[:n])); err != nil {
			return err
		}

		if err := p.renderProgressBar(); err != nil {
			return err
		}
	}

	_, err = stream.CloseAndRecv()
	return err
}

func (p *ProgressBar) sendBuffer(file *os.File, stream streamSender, createRequest func([]byte) interface{}) error {
	buf := make([]byte, bufferSize)

	for {
		n, err := file.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		err = p.updateProgress(n)
		if err != nil {
			return err
		}

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

func (p *ProgressBar) updateProgress(bytesRead int) error {
	if p.currentUploadedBytes+bytesRead > p.numberOfBytes {
		return fmt.Errorf("progress update exceeds total bytes: attempted to add %d bytes, but only %d bytes remain", bytesRead, p.numberOfBytes-p.currentUploadedBytes)
	}

	p.currentUploadedBytes += bytesRead
	p.currentUploadPercentage = p.currentUploadedBytes * 100 / p.numberOfBytes

	return nil
}

// Progress bar example: 📦 Uploading algorithm... [█████░░░░░░░░░░░░] [25%].
func (p *ProgressBar) renderProgressBar() error {
	var builder strings.Builder

	// Get terminal width.
	width, err := p.TerminalWidthFunc()
	if err != nil {
		if !warnOnlyOnce {
			color.Red("Progress bar could not be rendered")
			warnOnlyOnce = true
		}
		return nil
	}

	if p.maxWidth < width {
		p.maxWidth = width
	}

	if err := p.clearProgressBar(); err != nil {
		return fmt.Errorf("failed to clear progress bar: %v", err)
	}

	// Choose emoji based on operation type and content
	emoji := "🚀 "
	if strings.Contains(p.description, "data") {
		emoji = "📦 "
	} else if p.isDownload {
		emoji = "📥 "
	}

	if _, err := builder.WriteString(color.New(color.FgYellow).Sprint(emoji)); err != nil {
		return fmt.Errorf("failed to add emoji: %v", err)
	}

	// The progress bar starts with the description.
	description := color.New(color.FgYellow).Sprintf("%s ", p.description)
	if _, err := builder.WriteString(description); err != nil {
		return fmt.Errorf("failed to add description: %v", err)
	}

	// Add left bracket (colored).
	leftBracket := color.New(color.FgBlue).Sprint(leftBracket)
	if _, err := builder.WriteString(leftBracket); err != nil {
		return fmt.Errorf("failed to add left bracket: %v", err)
	}

	// Calculate the progress bar's width.
	progressWidth := width - builder.Len() - len(rightBracket+" [100%]")
	numOfCharactersBody := progressWidth * p.currentUploadPercentage / 100
	if numOfCharactersBody == 0 {
		numOfCharactersBody = 1
	}

	numOfCharactersPadding := progressWidth - numOfCharactersBody

	// Using unicode block characters for a smooth bar.
	progress := color.New(color.FgGreen).Sprint(strings.Repeat("█", numOfCharactersBody))
	if _, err := builder.WriteString(progress); err != nil {
		return fmt.Errorf("failed to add progress strings: %v", err)
	}

	// Add the unfilled part (light blocks as padding).
	padding := strings.Repeat("░", numOfCharactersPadding)
	if _, err := builder.WriteString(padding); err != nil {
		return fmt.Errorf("failed to add padding: %v", err)
	}

	// Add right bracket to progress bar.
	rightBracket := color.New(color.FgBlue).Sprint("]")
	if _, err := builder.WriteString(rightBracket); err != nil {
		return fmt.Errorf("failed to add right bracket: %v", err)
	}

	// Add the percentage at the end inside square brackets.
	strCurrentUploadPercentage := color.New(color.FgGreen).Sprintf(" [%d%%]", p.currentUploadPercentage)
	if _, err := builder.WriteString(strCurrentUploadPercentage); err != nil {
		return fmt.Errorf("failed to add upload percentage: %v", err)
	}

	// Write progress bar to the console.
	if _, err := io.WriteString(os.Stdout, builder.String()); err != nil {
		return fmt.Errorf("failed to write string: %v", err)
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

func (p *ProgressBar) ReceiveResult(description string, totalSize int, stream agent.AgentService_ResultClient, resultFile *os.File) error {
	return p.receiveStream(description, totalSize, func() ([]byte, error) {
		response, err := stream.Recv()
		if err != nil {
			return nil, err
		}

		return response.File, nil
	}, resultFile)
}

func (p *ProgressBar) ReceiveIMAMeasurements(description string, totalSize int, stream agent.AgentService_IMAMeasurementsClient, resultFile *os.File) ([]byte, error) {
	pcr10 := make([]byte, vtpm.Hash1)
	err := p.receiveStream(description, totalSize, func() ([]byte, error) {
		response, err := stream.Recv()
		if err != nil {
			return nil, err
		}

		copy(pcr10, response.Pcr10[:20])

		return response.File, nil
	}, resultFile)

	return pcr10, err
}

func (p *ProgressBar) ReceiveAttestation(description string, totalSize int, stream agent.AgentService_AttestationClient, attestationFile *os.File) error {
	return p.receiveStream(description, totalSize, func() ([]byte, error) {
		response, err := stream.Recv()
		if err != nil {
			return nil, err
		}

		return response.File, nil
	}, attestationFile)
}

func (p *ProgressBar) receiveStream(description string, totalSize int, recv func() ([]byte, error), file *os.File) error {
	p.reset(description, totalSize)
	p.isDownload = true

	for {
		chunk, err := recv()
		if err == io.EOF {
			if _, err := io.WriteString(os.Stdout, "\n"); err != nil {
				return err
			}
			break
		}
		if err != nil {
			return err
		}

		chunkSize := len(chunk)
		if err = p.updateProgress(chunkSize); err != nil {
			return err
		}

		if _, err := file.Write(chunk); err != nil {
			return err
		}
		if err := p.renderProgressBar(); err != nil {
			return err
		}
	}

	return nil
}
