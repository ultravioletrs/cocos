// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build embed
// +build embed

package quoteprovider

import (
	"github.com/google/go-sev-guest/client"
	"github.com/google/go-sev-guest/proto/sevsnp"
	pb "github.com/google/go-sev-guest/proto/sevsnp"
	cocosai "github.com/ultravioletrs/cocos"
)

const Nonce = 64

var _ client.LeveledQuoteProvider = (*embeddedQuoteProvider)(nil)

type embeddedQuoteProvider struct {
}

func GetLeveledQuoteProvider() (client.LeveledQuoteProvider, error) {
	return &embeddedQuoteProvider{}, nil
}

// GetRawQuoteAtLevel returns the SEV quote for the given report data and VMPL.
func (e *embeddedQuoteProvider) GetRawQuoteAtLevel(reportData [64]byte, vmpl uint) ([]byte, error) {
	return cocosai.EmbeddedAttestation, nil
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

func FetchAttestation(reportDataSlice []byte) ([]byte, error) {
	return cocosai.EmbeddedAttestation, nil
}

func VerifyAttestationReportTLS(attestation *sevsnp.Attestation, reportData []byte) error {
	return nil
}
