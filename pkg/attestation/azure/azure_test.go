// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"testing"
	"time"

	"github.com/edgelesssys/go-azguestattestation/maa"
	"github.com/stretchr/testify/assert"
)

func TestNewEnvConfigFromAgent(t *testing.T) {
	// Given
	expectedBuild := "CustomBuild123"
	expectedType := "Linux"
	expectedDistro := "UVC-Debian"
	expectedURL := "https://test.attest.azure.net"

	// When
	cfg := NewEnvConfigFromAgent(expectedBuild, expectedType, expectedDistro, expectedURL)

	// Then
	if cfg.OSBuild != expectedBuild {
		t.Errorf("expected OSBuild = %s, got %s", expectedBuild, cfg.OSBuild)
	}
	if cfg.OSType != expectedType {
		t.Errorf("expected OSType = %s, got %s", expectedType, cfg.OSType)
	}
	if cfg.OSDistro != expectedDistro {
		t.Errorf("expected OSDistro = %s, got %s", expectedDistro, cfg.OSDistro)
	}
	if cfg.MaaURL != expectedURL {
		t.Errorf("expected MaaURL = %s, got %s", expectedURL, cfg.MaaURL)
	}
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

func TestInitializeDefaultAzureTDXVars(t *testing.T) {
	oldURL := azureTDXIMDSQuoteURL
	oldDelay := azureTDXHCLRefreshDelay
	defer func() {
		azureTDXIMDSQuoteURL = oldURL
		azureTDXHCLRefreshDelay = oldDelay
	}()

	InitializeDefaultAzureTDXVars(" https://imds.example/tdquote ", 1500*time.Millisecond)

	assert.Equal(t, "https://imds.example/tdquote", azureTDXIMDSQuoteURL)
	assert.Equal(t, 1500*time.Millisecond, azureTDXHCLRefreshDelay)
}

func TestInitializeDefaultAzureTDXVarsFromEnv(t *testing.T) {
	oldURL := azureTDXIMDSQuoteURL
	oldDelay := azureTDXHCLRefreshDelay
	defer func() {
		azureTDXIMDSQuoteURL = oldURL
		azureTDXHCLRefreshDelay = oldDelay
	}()

	t.Setenv("AZURE_TDX_IMDS_URL", "https://env-imds.example/tdquote")
	t.Setenv("AZURE_HCL_REFRESH_WAIT", "2s")

	InitializeDefaultAzureTDXVarsFromEnv()

	assert.Equal(t, "https://env-imds.example/tdquote", azureTDXIMDSQuoteURL)
	assert.Equal(t, 2*time.Second, azureTDXHCLRefreshDelay)
}
