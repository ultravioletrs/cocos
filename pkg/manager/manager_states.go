// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

//go:generate stringer -type=ManagerState
type ManagerState uint8

const (
	VmProvision ManagerState = iota
	StopComputationRun
	VmRunning
)

//go:generate stringer -type=ManagerStatus
type ManagerStatus uint8

const (
	Starting ManagerStatus = iota
	Stopped
	Warning
	Disconnected
	Failed
)
