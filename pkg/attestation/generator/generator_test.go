// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package generator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCoRIM(t *testing.T) {
	opts := Options{
		Platform:    "snp",
		Measurement: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
	}

	corimBytes, err := GenerateCoRIM(opts)
	require.NoError(t, err)
	assert.NotEmpty(t, corimBytes)
}
