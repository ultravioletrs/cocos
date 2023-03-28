// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"net/http"

	"github.com/mainflux/mainflux"
)

var _ mainflux.Response = (*pingRes)(nil)

type pingRes struct {
	Greeting string `json:"greeting"`
}

func (res pingRes) Code() int {
	return http.StatusOK
}

func (res pingRes) Headers() map[string]string {
	return map[string]string{}
}

func (res pingRes) Empty() bool {
	return false
}

type createDomainRes struct {
	Name string `json:"name"`
}

func (res createDomainRes) Code() int {
	return http.StatusOK
}

func (res createDomainRes) Headers() map[string]string {
	return map[string]string{}
}

func (res createDomainRes) Empty() bool {
	return false
}
