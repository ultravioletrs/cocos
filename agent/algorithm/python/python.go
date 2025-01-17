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
	"github.com/ultravioletrs/cocos/agent/algorithm/logging"
	"github.com/ultravioletrs/cocos/agent/events"
	"google.golang.org/grpc/metadata"
)

const (
	PyRuntime    = "python3"
	PyRuntimeKey = "python_runtime"
)

func PythonRunTimeToContext(ctx context.Context, runtime string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, PyRuntimeKey, runtime)
}

func PythonRunTimeFromContext(ctx context.Context) string {
	return metadata.ValueFromIncomingContext(ctx, PyRuntimeKey)[0]
}

var _ algorithm.Algorithm = (*python)(nil)

type python struct {
	algoFile         string
	stderr           io.Writer
	stdout           io.Writer
	runtime          string
	requirementsFile string
	args             []string
	cmd              *exec.Cmd
}

func NewAlgorithm(logger *slog.Logger, eventsSvc events.Service, runtime, requirementsFile, algoFile string, args []string, cmpID string) algorithm.Algorithm {
	p := &python{
		algoFile:         algoFile,
		stderr:           &logging.Stderr{Logger: logger, EventSvc: eventsSvc, CmpID: cmpID},
		stdout:           &logging.Stdout{Logger: logger},
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

	updatePipCmd := exec.Command(pythonPath, "-m", "pip", "install", "--upgrade", "pip")
	updatePipCmd.Stderr = p.stderr
	updatePipCmd.Stdout = p.stdout
	if err := updatePipCmd.Run(); err != nil {
		return fmt.Errorf("error updating pip: %v", err)
	}

	if p.requirementsFile != "" {
		rcmd := exec.Command(pythonPath, "-m", "pip", "install", "-r", p.requirementsFile)
		rcmd.Stderr = p.stderr
		rcmd.Stdout = p.stdout
		if err := rcmd.Run(); err != nil {
			return fmt.Errorf("error installing requirements: %v", err)
		}
	}

	args := append([]string{p.algoFile}, p.args...)
	p.cmd = exec.Command(pythonPath, args...)
	p.cmd.Stderr = p.stderr
	p.cmd.Stdout = p.stdout

	if err := p.cmd.Start(); err != nil {
		return fmt.Errorf("error starting algorithm: %v", err)
	}

	if err := p.cmd.Wait(); err != nil {
		return fmt.Errorf("algorithm execution error: %v", err)
	}

	if err := os.RemoveAll(venvPath); err != nil {
		return fmt.Errorf("error removing virtual environment: %v", err)
	}

	return nil
}

func (p *python) Stop() error {
	if p.cmd == nil {
		return nil
	}

	if p.cmd.ProcessState != nil && p.cmd.ProcessState.Exited() {
		return nil
	}

	if err := p.cmd.Process.Kill(); err != nil {
		return fmt.Errorf("error stopping algorithm: %v", err)
	}

	return nil
}
