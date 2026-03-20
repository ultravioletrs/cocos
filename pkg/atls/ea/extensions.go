package ea

type Extension struct {
	Type uint16
	Data []byte
}

func MarshalExtensions(exts []Extension) ([]byte, error) {
	payloadLen := 0
	for _, e := range exts {
		if len(e.Data) > 0xFFFF {
			return nil, ErrInvalidLength
		}
		payloadLen += 4 + len(e.Data)
		if payloadLen > 0xFFFF {
			return nil, ErrInvalidLength
		}
	}
	out := make([]byte, 2+payloadLen)
	putUint16(out[0:2], uint16(payloadLen))
	off := 2
	for _, e := range exts {
		putUint16(out[off:off+2], e.Type)
		putUint16(out[off+2:off+4], uint16(len(e.Data)))
		copy(out[off+4:], e.Data)
		off += 4 + len(e.Data)
	}
	return out, nil
}

func UnmarshalExtensions(b []byte) (exts []Extension, rest []byte, err error) {
	if len(b) < 2 {
		return nil, nil, ErrTruncated
	}
	total := int(readUint16(b[0:2]))
	if len(b) < 2+total {
		return nil, nil, ErrTruncated
	}
	payload := b[2 : 2+total]
	rest = b[2+total:]
	i := 0
	for i < len(payload) {
		if len(payload)-i < 4 {
			return nil, nil, ErrTruncated
		}
		typ := readUint16(payload[i : i+2])
		l := int(readUint16(payload[i+2 : i+4]))
		i += 4
		if l < 0 || l > len(payload)-i {
			return nil, nil, ErrInvalidLength
		}
		data := make([]byte, l)
		copy(data, payload[i:i+l])
		i += l
		exts = append(exts, Extension{Type: typ, Data: data})
	}
	return exts, rest, nil
}
