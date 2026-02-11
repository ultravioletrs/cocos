// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package eat

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/ultravioletrs/cocos/pkg/attestation"
)

func TestIntUse(t *testing.T) {
	report := []byte("dummy-report")
	nonce := make([]byte, 8)

	claims, err := NewEATClaims(report, nonce, attestation.NoCC)
	assert.NoError(t, err)

	assert.Equal(t, IntUseGenericFresh, claims.IntUse)
}
