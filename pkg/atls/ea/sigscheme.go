package ea

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
)

type sigAlg uint8

const (
	sigAlgECDSA sigAlg = iota + 1
	sigAlgRSAPSS
	sigAlgEd25519
)

type sigSchemeInfo struct {
	Scheme uint16
	Alg    sigAlg
	Hash   crypto.Hash // 0 for Ed25519
}

func signatureSchemeInfo(s uint16) (sigSchemeInfo, error) {
	switch s {
	case uint16(tls.ECDSAWithP256AndSHA256):
		return sigSchemeInfo{s, sigAlgECDSA, crypto.SHA256}, nil
	case uint16(tls.PSSWithSHA256):
		return sigSchemeInfo{s, sigAlgRSAPSS, crypto.SHA256}, nil
	case uint16(tls.Ed25519):
		return sigSchemeInfo{s, sigAlgEd25519, 0}, nil
	default:
		return sigSchemeInfo{}, fmt.Errorf("%w: 0x%04x", ErrUnsupportedSignatureScheme, s)
	}
}

func chooseSignatureScheme(priv any, offered []uint16) (uint16, error) {
	compat := func(s uint16) bool {
		info, err := signatureSchemeInfo(s)
		if err != nil {
			return false
		}
		switch info.Alg {
		case sigAlgECDSA:
			k, ok := priv.(*ecdsa.PrivateKey)
			return ok && k.Curve.Params().Name == "P-256"
		case sigAlgRSAPSS:
			_, ok := priv.(*rsa.PrivateKey)
			return ok
		case sigAlgEd25519:
			_, ok := priv.(ed25519.PrivateKey)
			return ok
		default:
			return false
		}
	}

	if len(offered) > 0 {
		for _, s := range offered {
			if compat(s) {
				return s, nil
			}
		}
		return 0, ErrUnsupportedSignatureScheme
	}

	if k, ok := priv.(*ecdsa.PrivateKey); ok && k.Curve.Params().Name == "P-256" {
		return uint16(tls.ECDSAWithP256AndSHA256), nil
	}
	if _, ok := priv.(*rsa.PrivateKey); ok {
		return uint16(tls.PSSWithSHA256), nil
	}
	if _, ok := priv.(ed25519.PrivateKey); ok {
		return uint16(tls.Ed25519), nil
	}
	return 0, ErrUnsupportedSignatureScheme
}
