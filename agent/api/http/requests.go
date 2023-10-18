// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package http

import agent "github.com/ultravioletrs/agent/agent"

type runReq struct {
	computation agent.Computation
}

func (req runReq) validate() error {
	return nil
}
