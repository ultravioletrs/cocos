// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import "github.com/ultravioletrs/cocos/pkg/sdk"

var Verbose bool

type CLI struct {
	agentSDK sdk.SDK
}

func New(agentSDK sdk.SDK) *CLI {
	return &CLI{
		agentSDK: agentSDK,
	}
}
