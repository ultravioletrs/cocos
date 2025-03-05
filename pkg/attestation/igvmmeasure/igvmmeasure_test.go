// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package igvmmeasure

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIgvmMeasurement(t *testing.T) {
	tests := []struct {
		name         string
		setup        func() *IgvmMeasurement
		runArgs      string
		expectErr    bool
		expectedErr  string
		expectedIgvm bool
	}{
		{
			name: "NewIgvmMeasurement - Empty pathToFile",
			setup: func() *IgvmMeasurement {
				igvm, err := NewIgvmMeasurement("", nil, nil)
				assert.NotNil(t, err)
				assert.Nil(t, igvm) // Ensure it's nil
				return nil          // Explicitly return nil
			},
			expectErr:   true,
			expectedErr: "pathToFile cannot be empty",
		},
		{
			name: "NewIgvmMeasurement - Valid pathToFile",
			setup: func() *IgvmMeasurement {
				igvm, err := NewIgvmMeasurement("/valid/path", nil, nil)
				assert.Nil(t, err)
				assert.NotNil(t, igvm)
				return igvm
			},
			expectErr:   true,
			expectedErr: "no running process to stop",
		},
		{
			name: "Stop - No Process",
			setup: func() *IgvmMeasurement {
				return &IgvmMeasurement{}
			},
			expectErr:   true,
			expectedErr: "no running process to stop",
		},
		{
			name: "Stop - Success",
			setup: func() *IgvmMeasurement {
				process, err := os.StartProcess("/bin/sleep", []string{"sleep", "10"}, &os.ProcAttr{})
				assert.Nil(t, err)

				defer func() {
					if err := process.Kill(); err != nil {
						t.Logf("Failed to kill process: %v", err)
					}
				}()

				return &IgvmMeasurement{cmd: &exec.Cmd{Process: process}}
			},
		},
		{
			name: "Run - Successful Execution",
			setup: func() *IgvmMeasurement {
				return &IgvmMeasurement{
					pathToFile: "/valid/path",
					execCommand: func(name string, arg ...string) *exec.Cmd {
						cmd := exec.Command("sh", "-c", "echo 'measurement successful'")
						return cmd
					},
				}
			},
			expectErr:   false,
			expectedErr: "",
		},
		{
			name: "Run - Failure Execution",
			setup: func() *IgvmMeasurement {
				return &IgvmMeasurement{
					pathToFile: "/invalid/path",
					execCommand: func(name string, arg ...string) *exec.Cmd {
						cmd := exec.Command("sh", "-c", "echo 'some error occurred\nextra line' && exit 1")
						return cmd
					},
				}
			},
			expectErr:   true,
			expectedErr: "error: some error occurred\nextra line",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			igvm := tc.setup()

			if tc.expectedIgvm {
				assert.NotNil(t, igvm)
			}

			if igvm != nil {
				if strings.Contains(tc.name, "Run") {
					err := igvm.Run("/mock/igvmBinary")
					if tc.expectErr {
						assert.NotNil(t, err)
						assert.Equal(t, strings.TrimSpace(tc.expectedErr), strings.TrimSpace(err.Error()))
					} else {
						assert.Nil(t, err)
					}
				} else {
					err := igvm.Stop()
					if tc.expectErr {
						assert.NotNil(t, err)
						assert.Equal(t, tc.expectedErr, err.Error())
					} else {
						assert.Nil(t, err)
					}
				}
			}
		})
	}
}
