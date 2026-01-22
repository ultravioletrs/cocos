// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"encoding/base64"
	"encoding/json"

	cocosai "github.com/ultravioletrs/cocos"
)

var _ Provider = (*EmptyProvider)(nil)

type EmptyProvider struct{}

func (e *EmptyProvider) Attestation(teeNonce []byte, vTpmNonce []byte) ([]byte, error) {
	// For Sample/Empty provider, we treat the teeNonce as reportData
	return e.TeeAttestation(teeNonce)
}

func (e *EmptyProvider) TeeAttestation(teeNonce []byte) ([]byte, error) {
	// Generate dynamic JSON quote for Sample TEE (KBS compliant)
	type SampleQuote struct {
		Svn        string `json:"svn"`
		ReportData string `json:"report_data"`
	}

	quote := SampleQuote{
		Svn:        "1",
		ReportData: base64.StdEncoding.EncodeToString(teeNonce),
	}

	return json.Marshal(quote)
}

func (e *EmptyProvider) VTpmAttestation(vTpmNonce []byte) ([]byte, error) {
	return cocosai.EmbeddedAttestation, nil
}

func (e *EmptyProvider) AzureAttestationToken(nonce []byte) ([]byte, error) {
	return nil, nil
}
