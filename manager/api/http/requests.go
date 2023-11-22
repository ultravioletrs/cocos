// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package http

import "github.com/ultravioletrs/cocos/manager"

var _ apiReq = (*runReq)(nil)

type apiReq interface {
	validate() error
}

type runReq struct {
	Computation []byte `json:"computation,omitempty"`
}

func (req runReq) validate() error {
	if len(req.Computation) == 0 {
		return manager.ErrMalformedEntity
	}
	return nil
}
