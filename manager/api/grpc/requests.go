// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import "github.com/ultravioletrs/cocos/manager"

type runReq struct {
	Computation []byte `json:"computation,omitempty"`
}

func (req runReq) validate() error {
	if len(req.Computation) == 0 {
		return manager.ErrMalformedEntity
	}
	return nil
}
