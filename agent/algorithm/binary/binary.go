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
}

func NewAlgorithm(logger *slog.Logger, eventsSvc events.Service, algoFile string, args []string) algorithm.Algorithm {
	return &binary{
		algoFile: algoFile,
		stderr:   &logging.Stderr{Logger: logger, EventSvc: eventsSvc},
		stdout:   &logging.Stdout{Logger: logger},
		args:     args,
	}
}

func (b *binary) Run() error {
	cmd := exec.Command(b.algoFile, b.args...)
	cmd.Stderr = b.stderr
	cmd.Stdout = b.stdout

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("error starting algorithm: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("algorithm execution error: %v", err)
	}

	return nil
}
