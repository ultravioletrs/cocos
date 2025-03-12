// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package igvmmeasure

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
		setup       func() *IgvmMeasurement
		runArgs     string
		expectErr   bool
		expectedErr string
	}{
		{
			name: "NewIgvmMeasurement - Empty pathToBinary",
			setup: func() *IgvmMeasurement {
				igvm, err := NewIgvmMeasurement("", nil, nil)
				assert.Error(t, err)
				assert.Nil(t, igvm)
				return nil
			},
			expectErr:   true,
			expectedErr: "pathToBinary cannot be empty",
		},
		{
			name: "Run - Successful Execution",
			setup: func() *IgvmMeasurement {
				igvm, _ := NewIgvmMeasurement("/valid/path", nil, nil)
				igvm.SetExecCommand(func(name string, arg ...string) *exec.Cmd {
					return exec.Command("sh", "-c", "echo 'measurement successful'")
				})
				return igvm
			},
			expectErr: false,
		},
		{
			name: "Run - Failure Execution",
			setup: func() *IgvmMeasurement {
				igvm, _ := NewIgvmMeasurement("/invalid/path", nil, nil)
				igvm.SetExecCommand(func(name string, arg ...string) *exec.Cmd {
					return exec.Command("sh", "-c", "echo 'some error occurred\nextra line' && exit 1")
				})
				return igvm
			},
			expectErr:   true,
			expectedErr: "error: some error occurred\nextra line",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			igvm := tc.setup()

			if igvm != nil {
				buf := new(bytes.Buffer)
				igvm.stdout = buf
				igvm.stderr = buf

				err := igvm.Run(tc.runArgs)
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
