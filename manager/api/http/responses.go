// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package http

import (
	"net/http"

	"github.com/absmach/magistrala"
)

var (
	_ magistrala.Response = (*runRes)(nil)
	_ magistrala.Response = (*statusRes)(nil)
)

type runRes struct{}

func (res runRes) Code() int {
	return http.StatusOK
}

func (res runRes) Headers() map[string]string {
	return map[string]string{}
}

func (res runRes) Empty() bool {
	return true
}

type statusRes struct {
	Status string
}

func (res statusRes) Code() int {
	return http.StatusOK
}

func (res statusRes) Headers() map[string]string {
	return map[string]string{}
}

func (res statusRes) Empty() bool {
	return false
}
