// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package vtpm

type DummyRWC struct{}

// Read fills p with byte(len(p)) and returns len(p).
func (l *DummyRWC) Read(p []byte) (int, error) {
	n := len(p)
	// Fill each byte in p with the value of n as a byte.
	for i := range p {
		p[i] = byte(n)
	}
	return n, nil
}

// Write simply returns len(p) indicating that all bytes were written.
func (l *DummyRWC) Write(p []byte) (int, error) {
	// In this simple implementation, we ignore the data.
	return len(p), nil
}

func (l *DummyRWC) Close() error {
	return nil
}
