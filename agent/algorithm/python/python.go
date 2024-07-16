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
	pyRuntime  = "python3"
)

type PythonRunTimeKey struct{}

func PythonRunTimeToContext(ctx context.Context, runtime string) context.Context {
	return context.WithValue(ctx, PythonRunTimeKey{}, runtime)
}

func PythonRunTimeFromContext(ctx context.Context) (string, bool) {
	runtime, ok := ctx.Value(PythonRunTimeKey{}).(string)
	return runtime, ok
}

var _ algorithm.Algorithm = (*binary)(nil)

type binary struct {
	algoFile         string
	datasets         []string
	logger           *slog.Logger
	stderr           io.Writer
	stdout           io.Writer
	runtime          string
	requirementsFile string
}

func New(logger *slog.Logger, eventsSvc events.Service, runtime, requirementsFile, algoFile string, datasets ...string) algorithm.Algorithm {
	b := &binary{
		algoFile:         algoFile,
		datasets:         datasets,
		logger:           logger,
		stderr:           &algorithm.Stderr{Logger: logger, EventSvc: eventsSvc},
		stdout:           &algorithm.Stdout{Logger: logger},
		requirementsFile: requirementsFile,
	}
	if runtime != "" {
		b.runtime = runtime
	} else {
		b.runtime = pyRuntime
	}
	return b
}

func (b *binary) Run() ([]byte, error) {
	if b.requirementsFile != "" {
		rcmd := exec.Command(b.runtime, "-m", "pip", "install", "-r", b.requirementsFile)
		rcmd.Stderr = b.stderr
		rcmd.Stdout = b.stdout
		if err := rcmd.Run(); err != nil {
			return nil, fmt.Errorf("error installing requirements: %v", err)
		}
	}
	defer os.Remove(b.algoFile)
	defer func() {
		for _, file := range b.datasets {
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

	args := append([]string{b.algoFile, socketPath}, b.datasets...)
	cmd := exec.Command(b.runtime, args...)
	cmd.Stderr = b.stderr
	cmd.Stdout = b.stdout

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
