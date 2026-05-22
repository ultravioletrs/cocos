// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"os"
	"strings"
	"time"

	"github.com/edgelesssys/go-azguestattestation/maa"
)

type EnvConfig struct {
	OSBuild  string
	OSType   string
	OSDistro string
	MaaURL   string
}

func NewEnvConfigFromAgent(agentOSBuild, agentOSType, agentOSDistro, maaURL string) *EnvConfig {
	return &EnvConfig{
		OSBuild:  agentOSBuild,
		OSType:   agentOSType,
		OSDistro: agentOSDistro,
		MaaURL:   maaURL,
	}
}

func InitializeDefaultMAAVars(config *EnvConfig) {
	maa.OSBuild = config.OSBuild
	maa.OSType = config.OSType
	maa.OSDistro = config.OSDistro
	MaaURL = config.MaaURL
	InitializeDefaultAzureTDXVarsFromEnv()
}

func InitializeDefaultAzureTDXVars(imdsURL string, hclRefreshDelay time.Duration) {
	if imdsURL = strings.TrimSpace(imdsURL); imdsURL != "" {
		azureTDXIMDSQuoteURL = imdsURL
	}
	if hclRefreshDelay >= 0 {
		azureTDXHCLRefreshDelay = hclRefreshDelay
	}
}

func InitializeDefaultAzureTDXVarsFromEnv() {
	imdsURL := os.Getenv("AZURE_TDX_IMDS_URL")
	hclRefreshDelay := azureTDXHCLRefreshDelay
	if value := strings.TrimSpace(os.Getenv("AZURE_HCL_REFRESH_WAIT")); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			hclRefreshDelay = parsed
		}
	}
	InitializeDefaultAzureTDXVars(imdsURL, hclRefreshDelay)
}

func (c *EnvConfig) InitializeOSVars(build, osType, osDistro string) {
	if build != "" {
		c.OSBuild = build
	}
	if osType != "" {
		c.OSType = osType
	}
	if osDistro != "" {
		c.OSDistro = osDistro
	}
}
