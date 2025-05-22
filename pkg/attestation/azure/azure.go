// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package azure

import (
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
