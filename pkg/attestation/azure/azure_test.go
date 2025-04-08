// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"testing"

	"github.com/edgelesssys/go-azguestattestation/maa"
	"github.com/stretchr/testify/assert"
)

func TestNewEnvConfig(t *testing.T) {
	cfg := NewEnvConfig()

	assert.Equal(t, "UVC", cfg.OSBuild)
	assert.Equal(t, "Linux", cfg.OSType)
	assert.Equal(t, "UVC", cfg.OSDistro)
	assert.Equal(t, "https://sharedeus.eus.attest.azure.net", cfg.MaaURL)
}

func TestInitializeDefaultMAAVars(t *testing.T) {
	cfg := &EnvConfig{
		OSBuild:  "build123",
		OSType:   "CustomOS",
		OSDistro: "DistroX",
	}
	InitializeDefaultMAAVars(cfg)

	assert.Equal(t, "build123", maa.OSBuild)
	assert.Equal(t, "CustomOS", maa.OSType)
	assert.Equal(t, "DistroX", maa.OSDistro)
}

func TestInitializeOSVars(t *testing.T) {
	cfg := &EnvConfig{}
	cfg.InitializeOSVars("buildX", "TypeY", "DistroZ")

	assert.Equal(t, "buildX", cfg.OSBuild)
	assert.Equal(t, "TypeY", cfg.OSType)
	assert.Equal(t, "DistroZ", cfg.OSDistro)
}
