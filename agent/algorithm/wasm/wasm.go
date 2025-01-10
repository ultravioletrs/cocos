// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package wasm

import (
	"fmt"
	"io"
	"log/slog"
	"os/exec"

	"github.com/ultravioletrs/cocos/agent/algorithm"
	"github.com/ultravioletrs/cocos/agent/algorithm/logging"
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
	cmd      *exec.Cmd
}

func NewAlgorithm(logger *slog.Logger, eventsSvc events.Service, algoFile string, args []string, cmpID string) algorithm.Algorithm {
	return &wasm{
		algoFile: algoFile,
		stderr:   &logging.Stderr{Logger: logger, EventSvc: eventsSvc, CmpID: cmpID},
		stdout:   &logging.Stdout{Logger: logger},
		args:     args,
	}
}

func (w *wasm) Run() error {
	args := append(mapDirOption, w.algoFile)
	args = append(args, w.args...)
	w.cmd = exec.Command(wasmRuntime, args...)
	w.cmd.Stderr = w.stderr
	w.cmd.Stdout = w.stdout

	if err := w.cmd.Start(); err != nil {
		return fmt.Errorf("error starting algorithm: %v", err)
	}

	if err := w.cmd.Wait(); err != nil {
		return fmt.Errorf("algorithm execution error: %v", err)
	}

	return nil
}

func (w *wasm) Stop() error {
	if w.cmd == nil {
		return nil
	}

	if w.cmd.ProcessState != nil && w.cmd.ProcessState.Exited() {
		return nil
	}

	if err := w.cmd.Process.Kill(); err != nil {
		return fmt.Errorf("error stopping algorithm: %v", err)
	}

	return nil
}
