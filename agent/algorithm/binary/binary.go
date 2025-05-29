// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package binary

import (
	"fmt"
	"io"
	"log/slog"
	"os/exec"

	"github.com/ultravioletrs/cocos/agent/algorithm"
	"github.com/ultravioletrs/cocos/agent/algorithm/logging"
	"github.com/ultravioletrs/cocos/agent/events"
)

var _ algorithm.Algorithm = (*binary)(nil)

type binary struct {
	algoFile string
	stderr   io.Writer
	stdout   io.Writer
	args     []string
	cmd      *exec.Cmd
}

func NewAlgorithm(logger *slog.Logger, eventsSvc events.Service, algoFile string, args []string, cmpID string) algorithm.Algorithm {
	return &binary{
		algoFile: algoFile,
		stderr:   &logging.Stderr{Logger: logger, EventSvc: eventsSvc, CmpID: cmpID},
		stdout:   &logging.Stdout{Logger: logger},
		args:     args,
	}
}

func (b *binary) Run() error {
	b.cmd = exec.Command(b.algoFile, b.args...)
	b.cmd.Stderr = b.stderr
	b.cmd.Stdout = b.stdout

	if err := b.cmd.Start(); err != nil {
		return fmt.Errorf("error starting algorithm: %v", err)
	}

	if err := b.cmd.Wait(); err != nil {
		return fmt.Errorf("algorithm execution error: %v", err)
	}

	return nil
}

func (b *binary) Stop() error {
	if b.cmd == nil {
		return nil
	}

	if b.cmd.ProcessState != nil && b.cmd.ProcessState.Exited() {
		return nil
	}

	if b.cmd.Process == nil {
		return nil
	}

	if err := b.cmd.Process.Kill(); err != nil {
		return fmt.Errorf("error stopping algorithm: %v", err)
	}

	return nil
}
