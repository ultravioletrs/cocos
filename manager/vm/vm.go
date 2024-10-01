// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package vm

import (
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/pkg/manager"
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
	Transition(newState manager.ManagerState) error
	State() string
}

//go:generate mockery --name Provider --output=./mocks --filename provider.go --quiet --note "Copyright (c) Ultraviolet \n // SPDX-License-Identifier: Apache-2.0"
type Provider func(config interface{}, logsChan chan *manager.ClientStreamMessage, computationId string) VM
