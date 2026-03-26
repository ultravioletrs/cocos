// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package ea

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
)

type CertificateVerifyMessage struct {
	Algorithm uint16
	Signature []byte
}

func (m CertificateVerifyMessage) Marshal() ([]byte, error) {
	if len(m.Signature) > 0xFFFF {
		return nil, ErrInvalidLength
	}
	body := make([]byte, 4+len(m.Signature))
	putUint16(body[0:2], m.Algorithm)
	putUint16(body[2:4], uint16(len(m.Signature)))
	copy(body[4:], m.Signature)
	return MarshalHandshakeMessage(HandshakeMessage{Type: HandshakeTypeCertificateVerify, Body: body})
}

func UnmarshalCertificateVerifyMessage(handshakeBytes []byte) (CertificateVerifyMessage, []byte, error) {
	hm, rest, err := UnmarshalHandshakeMessage(handshakeBytes)
	if err != nil {
		return CertificateVerifyMessage{}, nil, err
	}
	if len(rest) != 0 || hm.Type != HandshakeTypeCertificateVerify {
		return CertificateVerifyMessage{}, nil, ErrInvalidLength
	}
	if len(hm.Body) < 4 {
		return CertificateVerifyMessage{}, nil, ErrTruncated
	}
	alg := readUint16(hm.Body[0:2])
	sigLen := int(readUint16(hm.Body[2:4]))
	if len(hm.Body) != 4+sigLen {
		return CertificateVerifyMessage{}, nil, ErrInvalidLength
	}
	sig := append([]byte(nil), hm.Body[4:]...)
	raw, _ := MarshalHandshakeMessage(hm)
	return CertificateVerifyMessage{Algorithm: alg, Signature: sig}, raw, nil
}

var eaContextString = []byte("Exported Authenticator")

func buildCertVerifyInput(transcriptHash []byte) []byte {
	prefix := bytes.Repeat([]byte{0x20}, 64)
	out := make([]byte, 0, len(prefix)+len(eaContextString)+1+len(transcriptHash))
	out = append(out, prefix...)
	out = append(out, eaContextString...)
	out = append(out, 0x00)
	out = append(out, transcriptHash...)
	return out
}

func signCertVerify(priv any, scheme uint16, transcriptHash []byte) ([]byte, error) {
	info, err := signatureSchemeInfo(scheme)
	if err != nil {
		return nil, err
	}
	msg := buildCertVerifyInput(transcriptHash)

	switch info.Alg {
	case sigAlgECDSA:
		k, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return nil, ErrUnsupportedSignatureScheme
		}
		h := info.Hash.New()
		h.Write(msg)
		return ecdsa.SignASN1(rand.Reader, k, h.Sum(nil))

	case sigAlgRSAPSS:
		k, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrUnsupportedSignatureScheme
		}
		h := info.Hash.New()
		h.Write(msg)
		return rsa.SignPSS(rand.Reader, k, info.Hash, h.Sum(nil),
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: info.Hash})

	case sigAlgEd25519:
		k, ok := priv.(ed25519.PrivateKey)
		if !ok {
			return nil, ErrUnsupportedSignatureScheme
		}
		return ed25519.Sign(k, msg), nil

	default:
		return nil, ErrUnsupportedSignatureScheme
	}
}

func verifyCertVerify(pub any, scheme uint16, transcriptHash []byte, signature []byte) error {
	info, err := signatureSchemeInfo(scheme)
	if err != nil {
		return err
	}
	msg := buildCertVerifyInput(transcriptHash)

	switch info.Alg {
	case sigAlgECDSA:
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return ErrUnsupportedSignatureScheme
		}
		h := info.Hash.New()
		h.Write(msg)
		if !ecdsa.VerifyASN1(k, h.Sum(nil), signature) {
			return ErrSignatureMismatch
		}
		return nil

	case sigAlgRSAPSS:
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			return ErrUnsupportedSignatureScheme
		}
		h := info.Hash.New()
		h.Write(msg)
		if err := rsa.VerifyPSS(k, info.Hash, h.Sum(nil), signature,
			&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: info.Hash}); err != nil {
			return ErrSignatureMismatch
		}
		return nil

	case sigAlgEd25519:
		k, ok := pub.(ed25519.PublicKey)
		if !ok {
			return ErrUnsupportedSignatureScheme
		}
		if !ed25519.Verify(k, msg, signature) {
			return ErrSignatureMismatch
		}
		return nil

	default:
		return ErrUnsupportedSignatureScheme
	}
}
