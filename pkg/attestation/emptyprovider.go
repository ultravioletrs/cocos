// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package attestation

import cocosai "github.com/ultravioletrs/cocos"

var _ Provider = (*EmptyProvider)(nil)

type EmptyProvider struct{}

func (e *EmptyProvider) Attestation(teeNonce []byte, vTpmNonce []byte) ([]byte, error) {
	return cocosai.EmbeddedAttestation, nil
}

func (e *EmptyProvider) TeeAttestation(teeNonce []byte) ([]byte, error) {
	return cocosai.EmbeddedAttestation, nil
}

func (e *EmptyProvider) VTpmAttestation(vTpmNonce []byte) ([]byte, error) {
	return cocosai.EmbeddedAttestation, nil
}

func (e *EmptyProvider) AzureAttestationToken(nonce []byte) ([]byte, error) {
	return nil, nil
}
