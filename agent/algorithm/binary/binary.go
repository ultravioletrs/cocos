// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package binary

import (
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

func NewAlgorithm(logger *slog.Logger, eventsSvc events.Service, algoFile string) algorithm.Algorithm {
	return &binary{
		algoFile: algoFile,
		logger:   logger,
		stderr:   &algorithm.Stderr{Logger: logger, EventSvc: eventsSvc},
		stdout:   &algorithm.Stdout{Logger: logger},
	}
}

func (b *binary) AddDataset(dataset string) {
	b.datasets = append(b.datasets, dataset)
}

func (b *binary) Run() ([]byte, error) {
	if err := os.Mkdir(algorithm.ResultsDir, 0o755); err != nil {
		return nil, fmt.Errorf("error creating results directory: %s", err.Error())
	}

	defer func() {
		for _, file := range b.datasets {
			if err := os.Remove(file); err != nil {
				b.logger.Error("error removing dataset file", slog.Any("error", err))
			}
		}
		if err := os.Remove(b.algoFile); err != nil {
			b.logger.Error("error removing algorithm file", slog.Any("error", err))
		}
		if err := os.Remove(algorithm.ResultsDir); err != nil {
			b.logger.Error("error removing results directory and its contents", slog.Any("error", err))
		}
	}()

	cmd := exec.Command(b.algoFile, b.datasets...)
	cmd.Stderr = b.stderr
	cmd.Stdout = b.stdout

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("error starting algorithm: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("algorithm execution error: %v", err)
	}

	results, err := algorithm.ZipDirectory()
	if err != nil {
		return nil, fmt.Errorf("error zipping results: %v", err)
	}

	return results, nil
}
