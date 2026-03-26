// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package ea

import (
	"crypto"
	"crypto/hmac"
	"crypto/subtle"
)

func hashConcat(h crypto.Hash, chunks ...[]byte) []byte {
	hs := h.New()
	for _, c := range chunks {
		if len(c) == 0 {
			continue
		}
		hs.Write(c)
	}
	return hs.Sum(nil)
}

func hmacSum(h crypto.Hash, key, data []byte) []byte {
	m := hmac.New(h.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
