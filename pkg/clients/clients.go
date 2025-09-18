// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package clients

import "time"

type ClientConfiguration interface {
	GetBaseConfig() BaseConfig
}

type BaseConfig struct {
	URL          string        `env:"URL"             envDefault:"localhost:7001"`
	Timeout      time.Duration `env:"TIMEOUT"         envDefault:"60s"`
	ClientCert   string        `env:"CLIENT_CERT"     envDefault:""`
	ClientKey    string        `env:"CLIENT_KEY"      envDefault:""`
	ServerCAFile string        `env:"SERVER_CA_CERTS" envDefault:""`
}

// AttestedClientConfig represents a client configuration with attested TLS capabilities
type AttestedClientConfig struct {
	BaseConfig
	AttestationPolicy string `env:"ATTESTATION_POLICY" envDefault:""`
	AttestedTLS       bool   `env:"ATTESTED_TLS"       envDefault:"false"`
	ProductName       string `env:"PRODUCT_NAME"       envDefault:"Milan"`
}

// StandardClientConfig represents a basic client configuration without attested TLS
type StandardClientConfig struct {
	BaseConfig
}

// Interface implementations
func (c BaseConfig) GetBaseConfig() BaseConfig {
	return c
}

func (c AttestedClientConfig) GetBaseConfig() BaseConfig {
	return c.BaseConfig
}

func (c StandardClientConfig) GetBaseConfig() BaseConfig {
	return c.BaseConfig
}

// Helper functions to create specific client types
func NewAttestedClient() AttestedClientConfig {
	return AttestedClientConfig{}
}

func NewStandardClient() StandardClientConfig {
	return StandardClientConfig{}
}
