// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"testing"
)

func TestManagerState_String(t *testing.T) {
	tests := []struct {
		state    ManagerState
		expected string
	}{
		{VmProvision, "VmProvision"},
		{StopComputationRun, "StopComputationRun"},
		{VmRunning, "VmRunning"},
		{ManagerState(3), "ManagerState(3)"},
		{ManagerState(100), "ManagerState(100)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.state.String(); got != tt.expected {
				t.Errorf("ManagerState.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestManagerStatus_String(t *testing.T) {
	tests := []struct {
		status   ManagerStatus
		expected string
	}{
		{Starting, "Starting"},
		{Stopped, "Stopped"},
		{Warning, "Warning"},
		{Disconnected, "Disconnected"},
		{ManagerStatus(4), "ManagerStatus(4)"},
		{ManagerStatus(100), "ManagerStatus(100)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.status.String(); got != tt.expected {
				t.Errorf("ManagerStatus.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}
