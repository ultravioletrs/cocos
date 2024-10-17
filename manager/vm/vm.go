// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package vm

import (
	"github.com/ultravioletrs/cocos/agent"
	pkgmanager "github.com/ultravioletrs/cocos/pkg/manager"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// VM represents a virtual machine.
//
//go:generate mockery --name VM --output=./mocks --filename vm.go --quiet --note "Copyright (c) Ultraviolet \n // SPDX-License-Identifier: Apache-2.0"
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

//go:generate mockery --name Provider --output=./mocks --filename provider.go --quiet --note "Copyright (c) Ultraviolet \n // SPDX-License-Identifier: Apache-2.0"
type Provider func(config interface{}, eventSender EventSender, computationId string) VM

type EventsLogs interface {
	IsEventLog() bool
}

type Event struct {
	EventType     string
	Timestamp     *timestamppb.Timestamp
	ComputationId string
	Details       []byte
	Originator    string
	Status        string
}

func (e *Event) IsEventLog() bool {
	return true
}

type Log struct {
	Message       string
	ComputationId string
	Level         string
	Timestamp     *timestamppb.Timestamp
}

func (l *Log) IsEventLog() bool {
	return true
}

type EventSender func(event EventsLogs) error
