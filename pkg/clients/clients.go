// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package clients

import "time"

var (
	_ ClientConfiguration = (*AttestedClientConfig)(nil)
	_ ClientConfiguration = (*StandardClientConfig)(nil)
)

type ClientConfiguration interface {
	Config() StandardClientConfig
}

// StandardClientConfig represents a basic client configuration without attested TLS.
type StandardClientConfig struct {
	URL          string        `env:"URL"             envDefault:"localhost:7001"`
	Timeout      time.Duration `env:"TIMEOUT"         envDefault:"60s"`
	ClientCert   string        `env:"CLIENT_CERT"     envDefault:""`
	ClientKey    string        `env:"CLIENT_KEY"      envDefault:""`
	ServerCAFile string        `env:"SERVER_CA_CERTS" envDefault:""`
}

// AttestedClientConfig represents a client configuration with attested TLS capabilities.
type AttestedClientConfig struct {
	StandardClientConfig
	AttestationPolicy string `env:"ATTESTATION_POLICY" envDefault:""`
	AttestedTLS       bool   `env:"ATTESTED_TLS"       envDefault:"false"`
	ProductName       string `env:"PRODUCT_NAME"       envDefault:"Milan"`
}

func (c AttestedClientConfig) Config() StandardClientConfig {
	return c.StandardClientConfig
}

func (c StandardClientConfig) Config() StandardClientConfig {
	return c
}
