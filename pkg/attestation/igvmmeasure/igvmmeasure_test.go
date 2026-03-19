// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package igvmmeasure

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// FakeExecCommand is a helper for mocking exec.Command.
func FakeExecCommand(name string, arg ...string) *exec.Cmd {
	args := append([]string{"-test.run=TestHelperProcess", "--", name}, arg...)
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "GO_WANT_HELPER_PROCESS=1")
	return cmd
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	args := os.Args
	for i := range args {
		if args[i] == "--" {
			args = args[i+1:]
			break
		}
	}

	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "No command provided\n")
		os.Exit(2)
	}

	cmd := args[0]
	if cmd == "error-bin" {
		fmt.Fprintf(os.Stderr, "some error")
		os.Exit(1)
	}

	if cmd == "multi-line-bin" {
		fmt.Fprintf(os.Stdout, "line 1\nline 2\n")
		os.Exit(0)
	}

	// Default behavior: print a single line of hex-like output
	fmt.Fprintf(os.Stdout, "00112233445566778899aabbccddeeff")
	os.Exit(0)
}

func TestNewIgvmMeasurement(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	m, err := NewIgvmMeasurement("igvm-bin", stderr, stdout)
	assert.NoError(t, err)
	assert.NotNil(t, m)
	assert.Equal(t, "igvm-bin", m.binPath)

	m2, err := NewIgvmMeasurement("", stderr, stdout)
	assert.Error(t, err)
	assert.Nil(t, m2)
}

func TestIgvmMeasurement_Run(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	m, err := NewIgvmMeasurement("igvm-bin", stderr, stdout)
	require.NoError(t, err)
	m.SetExecCommand(FakeExecCommand)

	err = m.Run("file.igvm")
	assert.NoError(t, err)
	assert.Equal(t, "00112233445566778899aabbccddeeff", stdout.String())

	// Test error from command
	m.binPath = "error-bin"
	err = m.Run("file.igvm")
	assert.Error(t, err)

	// Test error from multi-line output
	m.binPath = "multi-line-bin"
	stdout.Reset()
	err = m.Run("file.igvm")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error:")
}

func TestIgvmMeasurement_Stop_Success(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	m, err := NewIgvmMeasurement("igvm-bin", stderr, stdout)
	require.NoError(t, err)

	// Mock a command that sleeps so we can kill it
	cmd := exec.Command("sleep", "10")
	m.cmd = cmd
	err = cmd.Start()
	require.NoError(t, err)

	err = m.Stop()
	assert.NoError(t, err)
}

func TestIgvmMeasurement_Stop_Error(t *testing.T) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	m, err := NewIgvmMeasurement("igvm-bin", stderr, stdout)
	require.NoError(t, err)

	// No process running
	err = m.Stop()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no running process to stop")
}
