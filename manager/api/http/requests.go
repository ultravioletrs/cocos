// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package http

import (
	"github.com/ultravioletrs/cocos/agent"
)

var _ apiReq = (*runReq)(nil)

type apiReq interface {
	validate() error
}

type runReq struct {
	Computation agent.Computation `json:"computation"`
}

func (req *runReq) validate() error {
	return nil
}
