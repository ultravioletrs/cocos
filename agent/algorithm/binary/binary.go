// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package binary

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"

	"github.com/ultravioletrs/cocos/agent/algorithm"
	"github.com/ultravioletrs/cocos/agent/events"
)

const socketPath = "unix_socket"

var _ algorithm.Algorithm = (*binary)(nil)

type binary struct {
	algoFile string
	datasets []string
	logger   *slog.Logger
	stderr   io.Writer
	stdout   io.Writer
}

func New(logger *slog.Logger, eventsSvc events.Service, algoFile string, datasets ...string) algorithm.Algorithm {
	return &binary{
		algoFile: algoFile,
		datasets: datasets,
		logger:   logger,
		stderr:   &algorithm.Stderr{Logger: logger, EventSvc: eventsSvc},
		stdout:   &algorithm.Stdout{Logger: logger},
	}
}

func (b *binary) Run() ([]byte, error) {
	b.logger.Debug("testing stderr")
	defer os.Remove(b.algoFile)
	defer func() {
		for _, file := range b.datasets {
			os.Remove(file)
		}
	}()

	// Create channels for received data and errors
	dataChannel := make(chan []byte)
	errorChannel := make(chan error)

	var result []byte

	args := append([]string{socketPath}, b.datasets...)
	cmd := exec.Command(b.algoFile, args...)
	cmd.Stderr = b.stderr
	cmd.Stdout = &Stdout{DataChan: dataChannel, ErrorChan: errorChannel}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("error starting algorithm: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("algorithm execution error: %v", err)
	}

	select {
	case result = <-dataChannel:
		return result, nil
	case err := <-errorChannel:
		return nil, fmt.Errorf("error receiving data: %v", err)
	}
}

var _ io.Writer = &Stdout{}

const bufSize = 1024

type Stdout struct {
	DataChan  chan []byte
	ErrorChan chan error
}

// Write implements io.Writer.
func (s *Stdout) Write(p []byte) (n int, err error) {
	inBuf := bytes.NewBuffer(p)

	buf := make([]byte, bufSize)

	for {
		n, err := inBuf.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			s.ErrorChan <- err
			return len(p) - inBuf.Len(), err
		}

		s.DataChan <- buf[:n]
	}

	return len(p), nil
}
