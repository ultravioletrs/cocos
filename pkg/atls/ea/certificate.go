package ea

type CertificateMessage struct {
	Context []byte
	Entries []CertificateEntry
}

type CertificateEntry struct {
	CertDER    []byte
	Extensions []Extension
}

func (m CertificateMessage) Marshal() ([]byte, error) {
	if len(m.Context) > 255 {
		return nil, ErrInvalidLength
	}

	var listPayload []byte
	for _, e := range m.Entries {
		if len(e.CertDER) == 0 || len(e.CertDER) > 0xFFFFFF {
			return nil, ErrInvalidLength
		}
		extVec, err := MarshalExtensions(e.Extensions)
		if err != nil {
			return nil, err
		}
		entry := make([]byte, 3+len(e.CertDER)+len(extVec))
		putUint24(entry[0:3], uint32(len(e.CertDER)))
		copy(entry[3:], e.CertDER)
		copy(entry[3+len(e.CertDER):], extVec)
		listPayload = append(listPayload, entry...)
	}

	body := make([]byte, 1+len(m.Context)+3+len(listPayload))
	body[0] = byte(len(m.Context))
	copy(body[1:], m.Context)
	putUint24(body[1+len(m.Context):1+len(m.Context)+3], uint32(len(listPayload)))
	copy(body[1+len(m.Context)+3:], listPayload)

	return MarshalHandshakeMessage(HandshakeMessage{Type: HandshakeTypeCertificate, Body: body})
}

func UnmarshalCertificateMessage(handshakeBytes []byte) (CertificateMessage, []byte, error) {
	hm, rest, err := UnmarshalHandshakeMessage(handshakeBytes)
	if err != nil {
		return CertificateMessage{}, nil, err
	}
	if len(rest) != 0 || hm.Type != HandshakeTypeCertificate {
		return CertificateMessage{}, nil, ErrInvalidLength
	}
	if len(hm.Body) < 1 {
		return CertificateMessage{}, nil, ErrTruncated
	}

	ctxLen := int(hm.Body[0])
	if len(hm.Body) < 1+ctxLen+3 {
		return CertificateMessage{}, nil, ErrTruncated
	}
	ctx := append([]byte(nil), hm.Body[1:1+ctxLen]...)

	listLen := int(readUint24(hm.Body[1+ctxLen : 1+ctxLen+3]))
	if len(hm.Body) != 1+ctxLen+3+listLen {
		return CertificateMessage{}, nil, ErrInvalidLength
	}
	list := hm.Body[1+ctxLen+3:]

	var entries []CertificateEntry
	for i := 0; i < len(list); {
		if len(list)-i < 3 {
			return CertificateMessage{}, nil, ErrTruncated
		}
		certLen := int(readUint24(list[i : i+3]))
		i += 3
		if certLen <= 0 || certLen > len(list)-i {
			return CertificateMessage{}, nil, ErrInvalidLength
		}
		certDER := append([]byte(nil), list[i:i+certLen]...)
		i += certLen

		exts, leftover, err := UnmarshalExtensions(list[i:])
		if err != nil {
			return CertificateMessage{}, nil, err
		}
		consumed := len(list[i:]) - len(leftover)
		i += consumed

		entries = append(entries, CertificateEntry{CertDER: certDER, Extensions: exts})
	}

	raw, _ := MarshalHandshakeMessage(hm)
	return CertificateMessage{Context: ctx, Entries: entries}, raw, nil
}
