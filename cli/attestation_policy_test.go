// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAttestationPolicyCmd(t *testing.T) {
	c := &CLI{}
	cmd := c.NewAttestationPolicyCmd()

	assert.Equal(t, "policy [command]", cmd.Use)
	assert.Equal(t, "Change attestation policy", cmd.Short)
	assert.NotNil(t, cmd.Run)
}
