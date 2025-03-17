// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cmdconfig

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIgvmMeasurement(t *testing.T) {
	tests := []struct {
		name        string
		setup       func() *CmdConfig
		runArgs     string
		expectErr   bool
		expectedErr string
	}{
		{
			name: "NewIgvmMeasurement - Empty pathToBinary",
			setup: func() *CmdConfig {
				igvm, err := NewCmdConfig("", []string{""}, nil)
				assert.Error(t, err)
				assert.Nil(t, igvm)
				return nil
			},
			expectErr:   true,
			expectedErr: "pathToBinary cannot be empty",
		},
		{
			name: "Run - Successful Execution",
			setup: func() *CmdConfig {
				igvm, _ := NewCmdConfig("/valid/path", []string{""}, nil)
				igvm.SetExecCommand(func(name string, arg ...string) *exec.Cmd {
					return exec.Command("sh", "-c", "echo 'measurement successful'")
				})
				return igvm
			},
			expectErr: false,
		},
		{
			name: "Run - Failure Execution",
			setup: func() *CmdConfig {
				igvm, _ := NewCmdConfig("/invalid/path", []string{""}, nil)
				igvm.SetExecCommand(func(name string, arg ...string) *exec.Cmd {
					return exec.Command("sh", "-c", "echo 'some error occurred\nextra line' && exit 1")
				})
				return igvm
			},
			expectErr:   true,
			expectedErr: "exit status 1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			igvm := tc.setup()

			if igvm != nil {
				buf := new(bytes.Buffer)
				igvm.stderr = buf

				_, err := igvm.Run(tc.runArgs)
				if tc.expectErr {
					assert.Error(t, err)
					assert.Equal(t, strings.TrimSpace(tc.expectedErr), strings.TrimSpace(err.Error()))
				} else {
					assert.NoError(t, err)
				}
			}
		})
	}
}
