// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package atls

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestVerifyOptionsFromTLSConfig(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		if got := VerifyOptionsFromTLSConfig(nil); got != nil {
			t.Fatalf("expected nil verify options, got %#v", got)
		}
	})

	t.Run("skip verify disables ea chain validation", func(t *testing.T) {
		got := VerifyOptionsFromTLSConfig(&tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS13,
		})
		if got != nil {
			t.Fatalf("expected nil verify options for insecure skip verify, got %#v", got)
		}
	})

	t.Run("missing roots disables ea chain validation", func(t *testing.T) {
		got := VerifyOptionsFromTLSConfig(&tls.Config{
			MinVersion: tls.VersionTLS13,
		})
		if got != nil {
			t.Fatalf("expected nil verify options when roots are not configured, got %#v", got)
		}
	})

	t.Run("configured roots are propagated", func(t *testing.T) {
		roots := x509.NewCertPool()
		got := VerifyOptionsFromTLSConfig(&tls.Config{
			RootCAs:    roots,
			MinVersion: tls.VersionTLS13,
		})
		if got == nil {
			t.Fatal("expected verify options, got nil")
		}
		if got.Roots != roots {
			t.Fatal("expected verify options to reuse configured root CAs")
		}
	})
}
