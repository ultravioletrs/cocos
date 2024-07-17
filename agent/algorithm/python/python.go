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

	"github.com/ultravioletrs/cocos/agent/algorithm"
	"github.com/ultravioletrs/cocos/agent/events"
	"github.com/ultravioletrs/cocos/pkg/socket"
)

const (
	socketPath = "unix_socket"
	PyRuntime  = "python3"
)

type PythonRunTimeKey struct{}

func PythonRunTimeToContext(ctx context.Context, runtime string) context.Context {
	return context.WithValue(ctx, PythonRunTimeKey{}, runtime)
}

func PythonRunTimeFromContext(ctx context.Context) (string, bool) {
	runtime, ok := ctx.Value(PythonRunTimeKey{}).(string)
	return runtime, ok
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

func New(logger *slog.Logger, eventsSvc events.Service, runtime, requirementsFile, algoFile string) algorithm.Algorithm {
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
	if p.requirementsFile != "" {
		rcmd := exec.Command(p.runtime, "-m", "pip", "install", "-r", p.requirementsFile)
		rcmd.Stderr = p.stderr
		rcmd.Stdout = p.stdout
		if err := rcmd.Run(); err != nil {
			return nil, fmt.Errorf("error installing requirements: %v", err)
		}
	}
	defer os.Remove(p.algoFile)
	defer func() {
		for _, file := range p.datasets {
			os.Remove(file)
		}
	}()
	listener, err := socket.StartUnixSocketServer(socketPath)
	if err != nil {
		return nil, fmt.Errorf("error creating stdout pipe: %v", err)
	}
	defer listener.Close()

	// Create channels for received data and errors
	dataChannel := make(chan []byte)
	errorChannel := make(chan error)

	var result []byte

	go socket.AcceptConnection(listener, dataChannel, errorChannel)

	args := append([]string{p.algoFile, socketPath}, p.datasets...)
	cmd := exec.Command(p.runtime, args...)
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
