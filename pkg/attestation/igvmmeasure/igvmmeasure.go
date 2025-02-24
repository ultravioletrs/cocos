// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package igvmmeasure

import (
	"fmt"
	"io"
	"os/exec"
	"strings"
)

type IgvmMeasurement struct {
	pathToFile string
	options    []string
	stderr     io.Writer
	stdout     io.Writer
	cmd        *exec.Cmd
}

func NewIgvmMeasurement(pathToFile string, stderr, stdout io.Writer) (*IgvmMeasurement, error) {
	if pathToFile == "" {
		return nil, fmt.Errorf("pathToFile cannot be empty")
	}

	return &IgvmMeasurement{
		pathToFile: pathToFile,
		stderr:     stderr,
		stdout:     stdout,
	}, nil
}

func (m *IgvmMeasurement) Run(igvmBinaryPath string) error {
	binary := igvmBinaryPath
	args := []string{}
	args = append(args, m.options...)
	args = append(args, m.pathToFile)
	args = append(args, "measure")
	args = append(args, "-b")

	out, err := exec.Command(binary, args...).CombinedOutput()
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

	// Use os.Process.Kill() instead of syscall.SIGTERM
	if err := m.cmd.Process.Kill(); err != nil {
		return fmt.Errorf("failed to stop process: %v", err)
	}

	return nil
}
