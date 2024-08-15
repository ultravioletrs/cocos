// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package wasm

import (
	"fmt"
	"io"
	"log/slog"
	"os/exec"

	"github.com/ultravioletrs/cocos/agent/algorithm"
	"github.com/ultravioletrs/cocos/agent/events"
)

const wasmRuntime = "wasmedge"

var mapDirOption = []string{"--dir", ".:" + algorithm.ResultsDir}

var _ algorithm.Algorithm = (*wasm)(nil)

type wasm struct {
	algoFile string
	stderr   io.Writer
	stdout   io.Writer
	args     []string
}

func NewAlgorithm(logger *slog.Logger, eventsSvc events.Service, algoFile string, args []string) algorithm.Algorithm {
	return &wasm{
		algoFile: algoFile,
		stderr:   &algorithm.Stderr{Logger: logger, EventSvc: eventsSvc},
		stdout:   &algorithm.Stdout{Logger: logger},
		args:     args,
	}
}

func (w *wasm) Run() error {
	args := append(mapDirOption, w.algoFile)
	args = append(args, w.args...)
	cmd := exec.Command(wasmRuntime, args...)
	cmd.Stderr = w.stderr
	cmd.Stdout = w.stdout

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("error starting algorithm: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("algorithm execution error: %v", err)
	}

	return nil
}
