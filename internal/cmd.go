package internal

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// ExeShCmdStdout executes a shell command capturing the standard output
func ExeShCmdStdout(command string, args ...string) (string, error) {
	var stdoutBuf, stderrBuf bytes.Buffer

	cmd := exec.Command(command, args...)

	// Capture stdout and stderr using buffers
	cmd.Stdout = io.MultiWriter(&stdoutBuf, os.Stdout)
	cmd.Stderr = io.MultiWriter(&stderrBuf, os.Stderr)

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("error executing command '%s': %s", cmd.String(), err)
	}

	return stdoutBuf.String(), nil
}

// ExtractCmdAndArgs extracts the command and its arguments from the output string
func ExtractCmdAndArgs(cmdLine string, sudo bool) (string, []string) {
	lines := strings.Split(cmdLine, "\n")
	if len(lines) == 0 {
		return "", nil
	}

	parts := strings.Fields(lines[0])
	if len(parts) == 0 {
		return "", nil
	}

	if sudo {
		parts = append([]string{"sudo"}, parts...)
	}

	cmd := parts[0]
	args := parts[1:]

	return cmd, args
}

// RunCmdOutput runs the specified command and returns its standard output as a string
func RunCmdOutput(command string, args ...string) (string, error) {
	cmd := exec.Command(command, args...)

	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("error executing command '%s': %s", cmd.String(), err)
	}

	return string(output), nil
}

// RunCmdStart starts the specified command and returns the *exec.Cmd for the running process
func RunCmdStart(command string, args ...string) (*exec.Cmd, error) {
	cmd := exec.Command(command, args...)

	err := cmd.Start()
	if err != nil {
		return nil, fmt.Errorf("error starting command '%s': %s", cmd.String(), err)
	}

	return cmd, nil
}
