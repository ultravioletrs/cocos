// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package clients

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

var (
	_ ClientConfiguration = (*AttestedClientConfig)(nil)
	_ ClientConfiguration = (*StandardClientConfig)(nil)

	ErrInvalidAttestationRequestContext = errors.New("invalid attestation request context")
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
	// AttestationRequestContextHex, when set, is decoded from hex and used as
	// the exported authenticator certificate_request_context. This lets the
	// caller provide the background-check freshness value directly.
	AttestationRequestContextHex string `env:"ATTESTATION_REQUEST_CONTEXT" envDefault:""`
	// AttestationRequestContext allows callers inside the same process to pass
	// raw request-context bytes directly instead of using the hex string form.
	AttestationRequestContext []byte `env:"-"`
}

func (c AttestedClientConfig) Config() StandardClientConfig {
	return c.StandardClientConfig
}

func (c StandardClientConfig) Config() StandardClientConfig {
	return c
}

func (c AttestedClientConfig) RequestContext() ([]byte, error) {
	if len(c.AttestationRequestContext) > 0 {
		return append([]byte(nil), c.AttestationRequestContext...), nil
	}
	if c.AttestationRequestContextHex == "" {
		return nil, nil
	}
	requestContext, err := hex.DecodeString(c.AttestationRequestContextHex)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidAttestationRequestContext, err)
	}
	if len(requestContext) == 0 {
		return nil, fmt.Errorf("%w: decoded value is empty", ErrInvalidAttestationRequestContext)
	}
	return requestContext, nil
}
