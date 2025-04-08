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

func NewEnvConfig() *EnvConfig {
	return &EnvConfig{
		OSBuild:  "UVC",
		OSType:   "Linux",
		OSDistro: "UVC",
		MaaURL:   "https://sharedeus.eus.attest.azure.net",
	}
}

func InitializeDefaultMAAVars(config *EnvConfig) {
	maa.OSBuild = config.OSBuild
	maa.OSType = config.OSType
	maa.OSDistro = config.OSDistro
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
