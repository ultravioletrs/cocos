// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"github.com/ultravioletrs/cocos/agent"
)

type CLI struct {
	agentSDK agent.Service
}

func New(agentSDK agent.Service) *CLI {
	return &CLI{
		agentSDK: agentSDK,
	}
}
