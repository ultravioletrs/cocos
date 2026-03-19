// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package vtpm

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProvider_Methods(t *testing.T) {
	p := NewProvider(true, 1)

	originalExternalTPM := ExternalTPM
	defer func() { ExternalTPM = originalExternalTPM }()

	ExternalTPM = &mockTPM{Buffer: &bytes.Buffer{}}

	_, err := p.VTpmAttestation([]byte("nonce"))
	assert.Error(t, err)

	_, err = p.TeeAttestation([]byte("nonce"))
	assert.Error(t, err)
}
