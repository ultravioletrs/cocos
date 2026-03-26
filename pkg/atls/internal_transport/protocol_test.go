// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package internaltransport

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestReadFrameRejectsOversizedPayload(t *testing.T) {
	var buf bytes.Buffer
	header := make([]byte, 5)
	header[0] = frameTypeRequest
	binary.BigEndian.PutUint32(header[1:5], maxFramePayloadLen+1)
	if _, err := buf.Write(header); err != nil {
		t.Fatal(err)
	}

	_, _, err := readFrame(&buf)
	if err == nil {
		t.Fatal("expected oversized frame error")
	}
	if !strings.Contains(err.Error(), "frame payload too large") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWriteFrameRejectsOversizedPayload(t *testing.T) {
	payload := make([]byte, maxFramePayloadLen+1)
	err := writeFrame(bytes.NewBuffer(nil), frameTypeAuthenticator, payload)
	if err == nil {
		t.Fatal("expected oversized frame error")
	}
	if !strings.Contains(err.Error(), "frame payload too large") {
		t.Fatalf("unexpected error: %v", err)
	}
}
