// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package http

import (
	"net/http"

	"github.com/absmach/magistrala"
)

var _ magistrala.Response = (*runRes)(nil)

type runRes struct {
	AgentAddress string `json:"agent_address"`
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
