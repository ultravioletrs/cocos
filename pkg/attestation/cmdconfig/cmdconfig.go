// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cmdconfig

import (
	"bytes"
	"fmt"
	"io"
	"os/exec"
)

var IgvmMeasureOptions = []string{"measure", "-b"}

type MeasurementProvider interface {
	Run(binaryPath string) ([]byte, error)
	Stop() error
}
type CmdConfig struct {
	binPath     string
	options     []string
	stderr      io.Writer
	cmd         *exec.Cmd
	execCommand func(name string, arg ...string) *exec.Cmd
}

func NewCmdConfig(binPath string, options []string, stderr io.Writer) (*CmdConfig, error) {
	if binPath == "" {
		return nil, fmt.Errorf("pathToBinary cannot be empty")
	}

	return &CmdConfig{
		binPath:     binPath,
		options:     options,
		stderr:      stderr,
		execCommand: exec.Command,
	}, nil
}

func (m *CmdConfig) Run(pathToFile string) ([]byte, error) {
	binary := m.binPath
	args := []string{}
	args = append(args, pathToFile)
	args = append(args, m.options...)

	outBuf := &bytes.Buffer{}
	cmd := m.execCommand(binary, args...)
	cmd.Stderr = m.stderr
	cmd.Stdout = outBuf

	if err := cmd.Run(); err != nil {
		return nil, err
	}

	return outBuf.Bytes(), nil
}

func (m *CmdConfig) Stop() error {
	if m.cmd == nil || m.cmd.Process == nil {
		return fmt.Errorf("no running process to stop")
	}

	if err := m.cmd.Process.Kill(); err != nil {
		return fmt.Errorf("failed to stop process: %v", err)
	}

	return nil
}

// SetExecCommand allows tests to inject a mock execCommand function.
func (m *CmdConfig) SetExecCommand(cmdFunc func(name string, arg ...string) *exec.Cmd) {
	m.execCommand = cmdFunc
}
