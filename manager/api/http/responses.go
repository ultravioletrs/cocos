// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package http

import (
	"net/http"

	"github.com/absmach/magistrala"
)

var _ magistrala.Response = (*runRes)(nil)

type runRes struct {
	ID string `json:"id"`
}

func (res runRes) Code() int {
	return http.StatusOK
}

func (res runRes) Headers() map[string]string {
	return map[string]string{}
}

func (res runRes) Empty() bool {
	return false
}
