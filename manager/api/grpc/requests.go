// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"time"

	"github.com/ultravioletrs/cocos/manager"
)

type runReq struct {
	Computation []byte        `json:"computation,omitempty"`
	ClientTLS   bool          `json:"client_tls,omitempty"`
	CACerts     string        `json:"ca_certs,omitempty"`
	Timeout     time.Duration `json:"timeout,omitempty"`
}

func (req runReq) validate() error {
	if len(req.Computation) == 0 {
		return manager.ErrMalformedEntity
	}
	return nil
}
