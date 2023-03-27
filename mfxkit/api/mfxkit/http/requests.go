// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package http

import "github.com/mainflux/mfxkit/mfxkit"

type apiReq interface {
	validate() error
}

type pingReq struct {
	Secret string `json:"secret"`
}

func (req pingReq) validate() error {
	if req.Secret == "" {
		return mfxkit.ErrMalformedEntity
	}

	return nil
}
