// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package ea

import (
	"crypto/rand"
	"encoding/asn1"
)

const (
	SignatureAlgorithmsExtensionType     uint16 = 0x000d
	ServerNameExtensionType              uint16 = 0x0000
	CertificateAuthoritiesExtensionType  uint16 = 0x002f
	OIDFiltersExtensionType              uint16 = 0x0030
	SignatureAlgorithmsCertExtensionType uint16 = 0x0032
)

type AuthenticatorRequest struct {
	Type       uint8
	Context    []byte
	Extensions []Extension
}

type OIDFilter struct {
	OID    asn1.ObjectIdentifier
	Values []byte
}

func NewRandomContext(n int) ([]byte, error) {
	if n <= 0 || n > 255 {
		return nil, ErrInvalidLength
	}
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func (r AuthenticatorRequest) Marshal() ([]byte, error) {
	if r.Type != HandshakeTypeCertificateRequest && r.Type != HandshakeTypeClientCertificateRequest {
		return nil, ErrUnsupportedHandshakeType
	}
	if len(r.Context) > 255 {
		return nil, ErrInvalidLength
	}
	extVec, err := MarshalExtensions(r.Extensions)
	if err != nil {
		return nil, err
	}
	body := make([]byte, 1+len(r.Context)+len(extVec))
	body[0] = byte(len(r.Context))
	copy(body[1:], r.Context)
	copy(body[1+len(r.Context):], extVec)
	return MarshalHandshakeMessage(HandshakeMessage{Type: r.Type, Body: body})
}

func UnmarshalAuthenticatorRequest(handshakeBytes []byte) (AuthenticatorRequest, []byte, error) {
	hm, rest, err := UnmarshalHandshakeMessage(handshakeBytes)
	if err != nil {
		return AuthenticatorRequest{}, nil, err
	}
	if hm.Type != HandshakeTypeCertificateRequest && hm.Type != HandshakeTypeClientCertificateRequest {
		return AuthenticatorRequest{}, nil, ErrUnsupportedHandshakeType
	}
	if len(hm.Body) < 1 {
		return AuthenticatorRequest{}, nil, ErrTruncated
	}
	ctxLen := int(hm.Body[0])
	if len(hm.Body) < 1+ctxLen {
		return AuthenticatorRequest{}, nil, ErrTruncated
	}
	ctx := append([]byte(nil), hm.Body[1:1+ctxLen]...)
	exts, leftover, err := UnmarshalExtensions(hm.Body[1+ctxLen:])
	if err != nil {
		return AuthenticatorRequest{}, nil, err
	}
	if len(leftover) != 0 {
		return AuthenticatorRequest{}, nil, ErrInvalidLength
	}
	return AuthenticatorRequest{
		Type:       hm.Type,
		Context:    ctx,
		Extensions: exts,
	}, rest, nil
}

func (r AuthenticatorRequest) SignatureSchemes() ([]uint16, bool) {
	return parseSignatureSchemesExtension(r.Extensions, SignatureAlgorithmsExtensionType)
}

func (r AuthenticatorRequest) SignatureSchemesCert() ([]uint16, bool) {
	return parseSignatureSchemesExtension(r.Extensions, SignatureAlgorithmsCertExtensionType)
}

func (r AuthenticatorRequest) CertificateAuthorities() ([][]byte, bool) {
	for _, e := range r.Extensions {
		if e.Type != CertificateAuthoritiesExtensionType {
			continue
		}
		if len(e.Data) < 2 {
			return nil, false
		}
		total := int(readUint16(e.Data[0:2]))
		if total < 3 || len(e.Data) != 2+total {
			return nil, false
		}
		var out [][]byte
		for off := 2; off < len(e.Data); {
			if len(e.Data)-off < 2 {
				return nil, false
			}
			l := int(readUint16(e.Data[off : off+2]))
			off += 2
			if l == 0 || l > len(e.Data)-off {
				return nil, false
			}
			out = append(out, append([]byte(nil), e.Data[off:off+l]...))
			off += l
		}
		return out, true
	}
	return nil, false
}

func (r AuthenticatorRequest) OIDFilters() ([]OIDFilter, bool) {
	for _, e := range r.Extensions {
		if e.Type != OIDFiltersExtensionType {
			continue
		}
		if len(e.Data) < 2 {
			return nil, false
		}
		total := int(readUint16(e.Data[0:2]))
		if len(e.Data) != 2+total {
			return nil, false
		}
		var out []OIDFilter
		for off := 2; off < len(e.Data); {
			if len(e.Data)-off < 1 {
				return nil, false
			}
			oidLen := int(e.Data[off])
			off++
			if oidLen == 0 || oidLen > len(e.Data)-off {
				return nil, false
			}
			rawOID := append([]byte(nil), e.Data[off:off+oidLen]...)
			off += oidLen
			var oid asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(rawOID, &oid); err != nil {
				return nil, false
			}
			if len(e.Data)-off < 2 {
				return nil, false
			}
			valLen := int(readUint16(e.Data[off : off+2]))
			off += 2
			if valLen > len(e.Data)-off {
				return nil, false
			}
			values := append([]byte(nil), e.Data[off:off+valLen]...)
			off += valLen
			out = append(out, OIDFilter{OID: oid, Values: values})
		}
		return out, true
	}
	return nil, false
}

func parseSignatureSchemesExtension(exts []Extension, typ uint16) ([]uint16, bool) {
	for _, e := range exts {
		if e.Type != typ {
			continue
		}
		if len(e.Data) < 2 {
			return nil, false
		}
		vecLen := int(readUint16(e.Data[0:2]))
		if vecLen < 2 || vecLen%2 != 0 || len(e.Data) != 2+vecLen {
			return nil, false
		}
		out := make([]uint16, 0, vecLen/2)
		for off := 2; off < len(e.Data); off += 2 {
			out = append(out, readUint16(e.Data[off:off+2]))
		}
		return out, true
	}
	return nil, false
}

func SignatureAlgorithmsExtension(schemes []uint16) (Extension, error) {
	return marshalSignatureSchemesExtension(SignatureAlgorithmsExtensionType, schemes)
}

func SignatureAlgorithmsCertExtension(schemes []uint16) (Extension, error) {
	return marshalSignatureSchemesExtension(SignatureAlgorithmsCertExtensionType, schemes)
}

func marshalSignatureSchemesExtension(typ uint16, schemes []uint16) (Extension, error) {
	if len(schemes) == 0 {
		return Extension{}, ErrInvalidLength
	}
	if len(schemes) > 0x7fff {
		return Extension{}, ErrInvalidLength
	}
	data := make([]byte, 2+2*len(schemes))
	putUint16(data[0:2], uint16(2*len(schemes)))
	off := 2
	for _, s := range schemes {
		putUint16(data[off:off+2], s)
		off += 2
	}
	return Extension{Type: typ, Data: data}, nil
}
