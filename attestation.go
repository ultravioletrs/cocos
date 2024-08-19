// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build embed
// +build embed

package cocosai

import _ "embed"

//go:embed attestation.bin
var EmbeddedAttestation []byte
