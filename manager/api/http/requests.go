// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package http

import "github.com/ultravioletrs/manager/manager"

var (
	_ apiReq = (*runReq)(nil)
	_ apiReq = (*createLibvirtDomainReq)(nil)
)

type apiReq interface {
	validate() error
}

type createLibvirtDomainReq struct {
	Pool   string `json:"pool"`
	Volume string `json:"volume"`
	Domain string `json:"domain"`
}

func (req createLibvirtDomainReq) validate() error {
	return nil
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

type createQemuVMReq struct {
}

func (req createQemuVMReq) validate() error {
	return nil
}
