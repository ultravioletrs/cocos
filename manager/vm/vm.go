// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package vm

import (
	"log/slog"

	"github.com/ultravioletrs/cocos/agent"
	pkgmanager "github.com/ultravioletrs/cocos/pkg/manager"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// VM represents a virtual machine.
type VM interface {
	Start() error
	Stop() error
	SendAgentConfig(ac agent.Computation) error
	SetProcess(pid int) error
	GetProcess() int
	GetCID() int
	Transition(newState pkgmanager.ManagerState) error
	State() string
	GetConfig() interface{}
}

type Provider func(config interface{}, computationId string, logger *slog.Logger) VM

type Event struct {
	EventType     string
	Timestamp     *timestamppb.Timestamp
	ComputationId string
	Details       []byte
	Originator    string
	Status        string
}

type Log struct {
	Message       string
	ComputationId string
	Level         string
	Timestamp     *timestamppb.Timestamp
}
