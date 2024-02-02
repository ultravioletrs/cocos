// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"github.com/ultravioletrs/cocos/manager"
)

type clientStreamReq struct {
	*manager.ClientStreamMessage
}

func (req clientStreamReq) validate() error {
	return nil
}
