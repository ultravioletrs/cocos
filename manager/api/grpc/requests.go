// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"github.com/ultravioletrs/cocos/manager"
)

type runReq struct {
	Computation *manager.Computation `json:"computation"`
}

func (req runReq) validate() error {
	return nil
}
