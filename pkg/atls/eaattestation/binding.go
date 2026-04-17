// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
)

const (
	ExporterLabelAttestation    = "Attestation"
	ExportedAttestationValueLen = 32
)

var errNotTLS13 = errors.New("attestation: not TLS 1.3")

func ExportAttestationValue(st *tls.ConnectionState, label string, contextValue []byte) ([]byte, crypto.Hash, error) {
	if st.Version != tls.VersionTLS13 {
		return nil, 0, errNotTLS13
	}
	h, err := authenticatorHashTLS13(st.CipherSuite)
	if err != nil {
		return nil, 0, err
	}
	out, err := st.ExportKeyingMaterial(label, contextValue, ExportedAttestationValueLen)
	if err != nil {
		return nil, 0, err
	}
	return out, h, nil
}

func PublicKeyBytes(leaf *x509.Certificate) ([]byte, error) {
	if leaf == nil {
		return nil, fmt.Errorf("nil leaf cert")
	}
	if len(leaf.RawSubjectPublicKeyInfo) > 0 {
		return leaf.RawSubjectPublicKeyInfo, nil
	}
	b, err := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func AIKPublicKeyHash(h crypto.Hash, pubKey []byte) []byte {
	hs := h.New()
	hs.Write(pubKey)
	return hs.Sum(nil)
}

func BindingValue(h crypto.Hash, pubKey, exportedValue []byte) []byte {
	hs := h.New()
	hs.Write(pubKey)
	hs.Write(exportedValue)
	return hs.Sum(nil)
}

func ComputeBinding(st *tls.ConnectionState, label string, certificateRequestContext []byte, leaf *x509.Certificate) (exportedValue, aikPubHash, binding []byte, err error) {
	exportedValue, h, err := ExportAttestationValue(st, label, certificateRequestContext)
	if err != nil {
		return nil, nil, nil, err
	}
	pub, err := PublicKeyBytes(leaf)
	if err != nil {
		return nil, nil, nil, err
	}
	aikPubHash = AIKPublicKeyHash(h, pub)
	binding = BindingValue(h, pub, exportedValue)
	return exportedValue, aikPubHash, binding, nil
}

func authenticatorHashTLS13(cipherSuite uint16) (crypto.Hash, error) {
	switch cipherSuite {
	case tls.TLS_AES_128_GCM_SHA256, tls.TLS_CHACHA20_POLY1305_SHA256:
		return crypto.SHA256, nil
	case tls.TLS_AES_256_GCM_SHA384:
		return crypto.SHA384, nil
	default:
		return 0, fmt.Errorf("attestation: unknown cipher suite: %s (0x%04x)", tls.CipherSuiteName(cipherSuite), cipherSuite)
	}
}
