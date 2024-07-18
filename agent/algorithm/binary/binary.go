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
	b.logger.Debug("testing stderr 2")
	defer os.Remove(b.algoFile)
	defer func() {
		for _, file := range b.datasets {
			os.Remove(file)
		}
	}()

	var outBuf bytes.Buffer
	cmd := exec.Command(b.algoFile, b.datasets...)
	cmd.Stderr = b.stderr
	cmd.Stdout = io.MultiWriter(&outBuf, b.stdout)

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("error starting algorithm: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("algorithm execution error: %v", err)
	}

	return outBuf.Bytes(), nil
}
