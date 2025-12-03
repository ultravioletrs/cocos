// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build embed
// +build embed

package attestationpolicy

import (
	_ "embed"
)

//go:embed attestation_policy.json
var AttestationPolicy []byte
