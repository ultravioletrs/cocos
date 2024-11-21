// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build embed
// +build embed

package manager

import (
	"context"

	attestationPolicy "github.com/ultravioletrs/cocos/scripts/attestation_policy"
)

func (ms *managerService) FetchAttestationPolicy(_ context.Context, _ string) ([]byte, error) {
	return attestationPolicy.AttestationPolicy, nil
}
