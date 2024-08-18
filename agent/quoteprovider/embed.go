// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build embed
// +build embed

package quoteprovider

import (
	_ "embed"

	"github.com/google/go-sev-guest/client"
	pb "github.com/google/go-sev-guest/proto/sevsnp"
)

var _ client.QuoteProvider = (*embeddedQuoteProvider)(nil)

//go:embed attestation.bin
var embeddedAttestation []byte

type embeddedQuoteProvider struct {
}

func GetQuoteProvider() (client.QuoteProvider, error) {
	return &embeddedQuoteProvider{}, nil
}

// GetQuote returns the SEV quote for the given report data.
func (e *embeddedQuoteProvider) GetRawQuote(reportData [64]byte) ([]byte, error) {
	return embeddedAttestation, nil
}

// IsSupported returns true if the SEV platform is supported.
func (e *embeddedQuoteProvider) IsSupported() bool {
	return true
}

// Product returns the SEV product information.
// unimplemented since it is deprecated and not used.
func (e *embeddedQuoteProvider) Product() *pb.SevProduct {
	panic("unimplemented")
}
