// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build embed
// +build embed

package manager

import (
	_ "embed"
)

//go:embed scripts/backend_info/backend_info.json
var backendInfo []byte

func (ms *managerService) FetchBackendInfo() ([]byte, error) {
	return backendInfo, nil
}
