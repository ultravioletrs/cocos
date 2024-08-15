// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package python

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/ultravioletrs/cocos/agent/algorithm"
	"github.com/ultravioletrs/cocos/agent/events"
	"google.golang.org/grpc/metadata"
)

const (
	PyRuntime    = "python3"
	pyRuntimeKey = "python_runtime"
)

func PythonRunTimeToContext(ctx context.Context, runtime string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, pyRuntimeKey, runtime)
}

func PythonRunTimeFromContext(ctx context.Context) string {
	return metadata.ValueFromIncomingContext(ctx, pyRuntimeKey)[0]
}

var _ algorithm.Algorithm = (*python)(nil)

type python struct {
	algoFile         string
	stderr           io.Writer
	stdout           io.Writer
	runtime          string
	requirementsFile string
	args             []string
}

func NewAlgorithm(logger *slog.Logger, eventsSvc events.Service, runtime, requirementsFile, algoFile string, args []string) algorithm.Algorithm {
	p := &python{
		algoFile:         algoFile,
		stderr:           &algorithm.Stderr{Logger: logger, EventSvc: eventsSvc},
		stdout:           &algorithm.Stdout{Logger: logger},
		requirementsFile: requirementsFile,
		args:             args,
	}
	if runtime != "" {
		p.runtime = runtime
	} else {
		p.runtime = PyRuntime
	}
	return p
}

func (p *python) Run() error {
	venvPath := "venv"
	createVenvCmd := exec.Command(p.runtime, "-m", "venv", venvPath)
	createVenvCmd.Stderr = p.stderr
	createVenvCmd.Stdout = p.stdout
	if err := createVenvCmd.Run(); err != nil {
		return fmt.Errorf("error creating virtual environment: %v", err)
	}

	pythonPath := filepath.Join(venvPath, "bin", "python")

	if p.requirementsFile != "" {
		rcmd := exec.Command(pythonPath, "-m", "pip", "install", "-r", p.requirementsFile)
		rcmd.Stderr = p.stderr
		rcmd.Stdout = p.stdout
		if err := rcmd.Run(); err != nil {
			return fmt.Errorf("error installing requirements: %v", err)
		}
	}

	args := append([]string{p.algoFile}, p.args...)
	cmd := exec.Command(pythonPath, args...)
	cmd.Stderr = p.stderr
	cmd.Stdout = p.stdout

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("error starting algorithm: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("algorithm execution error: %v", err)
	}

	if err := os.RemoveAll(venvPath); err != nil {
		return fmt.Errorf("error removing virtual environment: %v", err)
	}

	return nil
}
