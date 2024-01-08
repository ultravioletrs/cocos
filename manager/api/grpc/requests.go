// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package grpc

import (
	"time"

	"github.com/ultravioletrs/cocos/manager"
)

type runReq struct {
	Computation *manager.Computation `json:"computation"`
	ClientTLS   bool                 `json:"client_tls,omitempty"`
	CACerts     string               `json:"ca_certs,omitempty"`
	Timeout     time.Duration        `json:"timeout,omitempty"`
}

func (req runReq) validate() error {
	return nil
}
