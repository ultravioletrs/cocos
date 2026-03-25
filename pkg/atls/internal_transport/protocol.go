// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package internaltransport

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	frameTypeRequest uint8 = iota + 1
	frameTypeAuthenticator
	maxFramePayloadLen = 16 << 20 // 16 MiB
)

func writeFrame(w io.Writer, typ uint8, payload []byte) error {
	if len(payload) > maxFramePayloadLen {
		return fmt.Errorf("atls: frame payload too large: %d", len(payload))
	}
	header := make([]byte, 5)
	header[0] = typ
	binary.BigEndian.PutUint32(header[1:5], uint32(len(payload)))
	if err := writeAll(w, header); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	return writeAll(w, payload)
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}

func readFrame(r io.Reader) (uint8, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	if header[0] == 0 {
		return 0, nil, fmt.Errorf("atls: invalid frame type")
	}
	n := binary.BigEndian.Uint32(header[1:5])
	if n > maxFramePayloadLen {
		return 0, nil, fmt.Errorf("atls: frame payload too large: %d", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return header[0], payload, nil
}
