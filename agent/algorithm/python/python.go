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
	"github.com/ultravioletrs/cocos/pkg/socket"
	"google.golang.org/grpc/metadata"
)

const (
	socketPath   = "unix_socket"
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
	datasets         []string
	logger           *slog.Logger
	stderr           io.Writer
	stdout           io.Writer
	runtime          string
	requirementsFile string
}

func NewAlgorithm(logger *slog.Logger, eventsSvc events.Service, runtime, requirementsFile, algoFile string) algorithm.Algorithm {
	p := &python{
		algoFile:         algoFile,
		logger:           logger,
		stderr:           &algorithm.Stderr{Logger: logger, EventSvc: eventsSvc},
		stdout:           &algorithm.Stdout{Logger: logger},
		requirementsFile: requirementsFile,
	}
	if runtime != "" {
		p.runtime = runtime
	} else {
		p.runtime = PyRuntime
	}
	return p
}

func (p *python) AddDataset(dataset string) {
	p.datasets = append(p.datasets, dataset)
}

func (p *python) Run() ([]byte, error) {
	venvPath := "venv"
	createVenvCmd := exec.Command(p.runtime, "-m", "venv", venvPath)
	createVenvCmd.Stderr = p.stderr
	createVenvCmd.Stdout = p.stdout
	if err := createVenvCmd.Run(); err != nil {
		return nil, fmt.Errorf("error creating virtual environment: %v", err)
	}

	pythonPath := filepath.Join(venvPath, "bin", "python")

	if p.requirementsFile != "" {
		rcmd := exec.Command(pythonPath, "-m", "pip", "install", "-r", p.requirementsFile)
		rcmd.Stderr = p.stderr
		rcmd.Stdout = p.stdout
		if err := rcmd.Run(); err != nil {
			return nil, fmt.Errorf("error installing requirements: %v", err)
		}
	}

	defer func() {
		for _, file := range p.datasets {
			if err := os.Remove(file); err != nil {
				p.logger.Error("error removing dataset file", slog.Any("error", err))
			}
		}
		if err := os.Remove(p.algoFile); err != nil {
			p.logger.Error("error removing algorithm file", slog.Any("error", err))
		}
		if err := os.RemoveAll(venvPath); err != nil {
			p.logger.Error("error removing virtual environment", slog.Any("error", err))
		}
	}()

	listener, err := socket.StartUnixSocketServer(socketPath)
	if err != nil {
		return nil, fmt.Errorf("error creating stdout pipe: %v", err)
	}
	defer listener.Close()

	dataChannel := make(chan []byte)
	errorChannel := make(chan error)

	var result []byte

	go socket.AcceptConnection(listener, dataChannel, errorChannel)

	args := append([]string{p.algoFile, socketPath}, p.datasets...)
	cmd := exec.Command(pythonPath, args...)
	cmd.Stderr = p.stderr
	cmd.Stdout = p.stdout

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("error starting algorithm: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("algorithm execution error: %v", err)
	}

	select {
	case result = <-dataChannel:
		return result, nil
	case err = <-errorChannel:
		return nil, fmt.Errorf("error receiving data: %v", err)
	}
}
