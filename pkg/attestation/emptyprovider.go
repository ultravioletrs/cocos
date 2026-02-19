// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"fmt"

	cocosai "github.com/ultravioletrs/cocos"
)

var _ Provider = (*EmptyProvider)(nil)

type EmptyProvider struct{}

func (e *EmptyProvider) Attestation(teeNonce []byte, vTpmNonce []byte) ([]byte, error) {
	// For Sample/Empty provider, we treat the teeNonce as reportData
	return e.TeeAttestation(teeNonce)
}

func (e *EmptyProvider) TeeAttestation(teeNonce []byte) ([]byte, error) {
	// EmptyProvider should not be used for attestation
	// The CC Attestation Agent's sample attester should be used instead
	return nil, fmt.Errorf("EmptyProvider should not be used - configure USE_CC_ATTESTATION_AGENT=true to use the CC Attestation Agent's sample attester")
}

func (e *EmptyProvider) VTpmAttestation(vTpmNonce []byte) ([]byte, error) {
	return cocosai.EmbeddedAttestation, nil
}

func (e *EmptyProvider) AzureAttestationToken(nonce []byte) ([]byte, error) {
	return nil, nil
}
