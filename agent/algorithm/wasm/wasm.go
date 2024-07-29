// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package wasm

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"

	"github.com/ultravioletrs/cocos/agent/algorithm"
	"github.com/ultravioletrs/cocos/agent/events"
)

const (
	wasmRuntime  = "wasmedge"
	outputDir    = "output"
	mapDirOption = "--dir .:" + outputDir
)

var _ algorithm.Algorithm = (*wasm)(nil)

type wasm struct {
	algoFile        string
	resultsFilePath string
	datasets        []string
	logger          *slog.Logger
	stderr          io.Writer
	stdout          io.Writer
}

func NewAlgorithm(logger *slog.Logger, eventsSvc events.Service, algoFile, resultsFilePath string) algorithm.Algorithm {
	return &wasm{
		algoFile:        algoFile,
		resultsFilePath: resultsFilePath,
		logger:          logger,
		stderr:          &algorithm.Stderr{Logger: logger, EventSvc: eventsSvc},
		stdout:          &algorithm.Stdout{Logger: logger},
	}
}

func (w *wasm) AddDataset(dataset string) {
	w.datasets = append(w.datasets, dataset)
}

func (w *wasm) Run() ([]byte, error) {
	if err := os.Mkdir("output", 0o755); err != nil {
		return nil, fmt.Errorf("error creating output directory: %s", err.Error())
	}

	defer func() {
		for _, file := range w.datasets {
			if err := os.Remove(file); err != nil {
				w.logger.Error("error removing dataset file", slog.Any("error", err))
			}
		}
		if err := os.Remove(w.algoFile); err != nil {
			w.logger.Error("error removing algorithm file", slog.Any("error", err))
		}
		if err := os.Remove(outputDir); err != nil {
			w.logger.Error("error removing output directory", slog.Any("error", err))
		}
	}()

	args := append([]string{mapDirOption, w.algoFile}, w.datasets...)
	cmd := exec.Command(wasmRuntime, args...)
	cmd.Stderr = w.stderr
	cmd.Stdout = w.stdout

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("error starting algorithm: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("algorithm execution error: %v", err)
	}

	results, err := os.ReadFile(outputDir + w.resultsFilePath)
	if err != nil {
		return nil, fmt.Errorf("error reading results file: %v", err)
	}

	return results, nil
}
