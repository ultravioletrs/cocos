// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package ea

import (
	"crypto"
	"crypto/tls"
	"fmt"
)

const (
	LabelClientAuthenticatorHandshakeContext = "EXPORTER-client authenticator handshake context"
	LabelServerAuthenticatorHandshakeContext = "EXPORTER-server authenticator handshake context"
	LabelClientAuthenticatorFinishedKey      = "EXPORTER-client authenticator finished key"
	LabelServerAuthenticatorFinishedKey      = "EXPORTER-server authenticator finished key"
)

type Role uint8

const (
	RoleClient Role = iota + 1
	RoleServer
)

func AuthenticatorHashTLS13(cipherSuite uint16) (crypto.Hash, error) {
	switch cipherSuite {
	case tls.TLS_AES_128_GCM_SHA256, tls.TLS_CHACHA20_POLY1305_SHA256:
		return crypto.SHA256, nil
	case tls.TLS_AES_256_GCM_SHA384:
		return crypto.SHA384, nil
	default:
		return 0, fmt.Errorf("%w: %s (0x%04x)", ErrUnknownCipherSuite, tls.CipherSuiteName(cipherSuite), cipherSuite)
	}
}

func ExportHandshakeContext(st *tls.ConnectionState, role Role) ([]byte, crypto.Hash, error) {
	if st.Version != tls.VersionTLS13 {
		return nil, 0, ErrNotTLS13
	}
	h, err := AuthenticatorHashTLS13(st.CipherSuite)
	if err != nil {
		return nil, 0, err
	}
	label := LabelClientAuthenticatorHandshakeContext
	if role == RoleServer {
		label = LabelServerAuthenticatorHandshakeContext
	}
	out, err := st.ExportKeyingMaterial(label, nil, h.Size())
	return out, h, err
}

func ExportFinishedKey(st *tls.ConnectionState, role Role) ([]byte, crypto.Hash, error) {
	if st.Version != tls.VersionTLS13 {
		return nil, 0, ErrNotTLS13
	}
	h, err := AuthenticatorHashTLS13(st.CipherSuite)
	if err != nil {
		return nil, 0, err
	}
	label := LabelClientAuthenticatorFinishedKey
	if role == RoleServer {
		label = LabelServerAuthenticatorFinishedKey
	}
	out, err := st.ExportKeyingMaterial(label, nil, h.Size())
	return out, h, err
}
