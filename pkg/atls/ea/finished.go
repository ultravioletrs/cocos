package ea

type FinishedMessage struct {
	VerifyData []byte
}

func (m FinishedMessage) Marshal() ([]byte, error) {
	if len(m.VerifyData) == 0 {
		return nil, ErrInvalidLength
	}
	return MarshalHandshakeMessage(HandshakeMessage{Type: HandshakeTypeFinished, Body: append([]byte(nil), m.VerifyData...)})
}

func UnmarshalFinishedMessage(handshakeBytes []byte) (FinishedMessage, []byte, error) {
	hm, rest, err := UnmarshalHandshakeMessage(handshakeBytes)
	if err != nil {
		return FinishedMessage{}, nil, err
	}
	if len(rest) != 0 || hm.Type != HandshakeTypeFinished || len(hm.Body) == 0 {
		return FinishedMessage{}, nil, ErrInvalidLength
	}
	raw, _ := MarshalHandshakeMessage(hm)
	return FinishedMessage{VerifyData: append([]byte(nil), hm.Body...)}, raw, nil
}
