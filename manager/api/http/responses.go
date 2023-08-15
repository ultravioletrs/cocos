// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"net/http"

	"github.com/mainflux/mainflux"
)

var (
	_ mainflux.Response = (*createLibvirtDomainRes)(nil)
	_ mainflux.Response = (*runRes)(nil)
)

type createLibvirtDomainRes struct {
	Name string `json:"name"`
}

func (res createLibvirtDomainRes) Code() int {
	return http.StatusOK
}

func (res createLibvirtDomainRes) Headers() map[string]string {
	return map[string]string{}
}

func (res createLibvirtDomainRes) Empty() bool {
	return false
}

type createQemuVMRes struct {
	Path string `json:"path"`
	Args string `json:"args"`
}

func (res createQemuVMRes) Code() int {
	return http.StatusOK
}

func (res createQemuVMRes) Headers() map[string]string {
	return map[string]string{}
}

func (res createQemuVMRes) Empty() bool {
	return false
}

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
