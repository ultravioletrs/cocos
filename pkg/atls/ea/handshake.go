// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package ea

const handshakeHeaderLen = 4 // 1 byte type + 3 byte uint24 len

const (
	HandshakeTypeCertificate              uint8 = 11
	HandshakeTypeCertificateRequest       uint8 = 13
	HandshakeTypeCertificateVerify        uint8 = 15
	HandshakeTypeClientCertificateRequest uint8 = 17
	HandshakeTypeFinished                 uint8 = 20
)

type HandshakeMessage struct {
	Type uint8
	Body []byte
}

func MarshalHandshakeMessage(m HandshakeMessage) ([]byte, error) {
	if len(m.Body) > 0xFFFFFF {
		return nil, ErrInvalidLength
	}
	out := make([]byte, handshakeHeaderLen+len(m.Body))
	out[0] = m.Type
	putUint24(out[1:4], uint32(len(m.Body)))
	copy(out[4:], m.Body)
	return out, nil
}

func UnmarshalHandshakeMessage(b []byte) (msg HandshakeMessage, rest []byte, err error) {
	if len(b) < handshakeHeaderLen {
		return HandshakeMessage{}, nil, ErrTruncated
	}
	t := b[0]
	n := int(readUint24(b[1:4]))
	if n < 0 || n > 0xFFFFFF {
		return HandshakeMessage{}, nil, ErrInvalidLength
	}
	if len(b) < handshakeHeaderLen+n {
		return HandshakeMessage{}, nil, ErrTruncated
	}
	body := make([]byte, n)
	copy(body, b[4:4+n])
	return HandshakeMessage{Type: t, Body: body}, b[4+n:], nil
}

func putUint24(dst []byte, v uint32) { dst[0] = byte(v >> 16); dst[1] = byte(v >> 8); dst[2] = byte(v) }
func readUint24(src []byte) uint32 {
	return (uint32(src[0]) << 16) | (uint32(src[1]) << 8) | uint32(src[2])
}

func putUint16(dst []byte, v uint16) { dst[0] = byte(v >> 8); dst[1] = byte(v) }
func readUint16(src []byte) uint16   { return (uint16(src[0]) << 8) | uint16(src[1]) }
