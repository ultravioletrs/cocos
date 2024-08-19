// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build embed
// +build embed

package backendinfo

import (
	_ "embed"
)

//go:embed backend_info.json
var BackendInfo []byte
