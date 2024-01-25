// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"github.com/ultravioletrs/cocos/agent"
	"github.com/ultravioletrs/cocos/manager"
)

type CLI struct {
	agentSDK   agent.Service
	managerSDK manager.Service
}

func New(agentSDK agent.Service, managerSDK manager.Service) *CLI {
	return &CLI{
		agentSDK:   agentSDK,
		managerSDK: managerSDK,
	}
}
