// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package http

import "github.com/ultravioletrs/cocos-ai/agent"

type runReq struct {
	computation agent.Computation
}

func (req runReq) validate() error {
	return nil
}
