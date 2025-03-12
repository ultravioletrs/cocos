// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package igvmmeasure

import (
	"fmt"
	"io"
	"os/exec"
	"strings"
)

type MeasurementProvider interface {
	Run(igvmBinaryPath string) error
	Stop() error
}
type IgvmMeasurement struct {
	binPath     string
	options     []string
	stderr      io.Writer
	stdout      io.Writer
	cmd         *exec.Cmd
	execCommand func(name string, arg ...string) *exec.Cmd
}

func NewIgvmMeasurement(binPath string, stderr, stdout io.Writer) (*IgvmMeasurement, error) {
	if binPath == "" {
		return nil, fmt.Errorf("pathToBinary cannot be empty")
	}

	return &IgvmMeasurement{
		binPath:     binPath,
		stderr:      stderr,
		stdout:      stdout,
		execCommand: exec.Command,
	}, nil
}

func (m *IgvmMeasurement) Run(pathToFile string) error {
	binary := m.binPath
	args := []string{}
	args = append(args, m.options...)
	args = append(args, pathToFile)
	args = append(args, "measure")
	args = append(args, "-b")

	out, err := m.execCommand(binary, args...).CombinedOutput()
	if err != nil {
		fmt.Println("Error:", err)
	}
	outputString := string(out)

	lines := strings.Split(strings.TrimSpace(outputString), "\n")

	if len(lines) == 1 {
		outputString = strings.ToLower(outputString)
		fmt.Print(outputString)
	} else {
		return fmt.Errorf("error: %s", outputString)
	}

	return nil
}

func (m *IgvmMeasurement) Stop() error {
	if m.cmd == nil || m.cmd.Process == nil {
		return fmt.Errorf("no running process to stop")
	}

	if err := m.cmd.Process.Kill(); err != nil {
		return fmt.Errorf("failed to stop process: %v", err)
	}

	return nil
}

// SetExecCommand allows tests to inject a mock execCommand function.
func (m *IgvmMeasurement) SetExecCommand(cmdFunc func(name string, arg ...string) *exec.Cmd) {
	m.execCommand = cmdFunc
}
