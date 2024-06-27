// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import "github.com/ultravioletrs/cocos/pkg/sdk"

type CLI struct {
	agentSDK sdk.SDK
	keyType  string
}

func New(agentSDK sdk.SDK, keyType string) *CLI {
	return &CLI{
		agentSDK: agentSDK,
		keyType:  keyType,
	}
}
