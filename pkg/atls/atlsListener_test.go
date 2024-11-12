// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package atls

import (
	"testing"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func TestListen(t *testing.T) {
	cert := []byte("dummy_cert")
	key := []byte("dummy_key")

	cases := []struct {
		name    string
		address string
		err     error
	}{
		{
			name:    "Valid address",
			address: "127.0.0.1:8889",
			err:     nil,
		},
		{
			name:    "Invalid address format",
			address: "127.0.0.1",
			err:     errListener,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l, err := Listen(c.address, cert, key)
			assert.True(t, errors.Contains(err, c.err))
			if l != nil {
				t.Cleanup(func() {
					err := l.Close()
					assert.NoError(t, err)
				})
			}
		})
	}
}

func TestATLSServerListener_Accept(t *testing.T) {
	t.Run("Accepts connection", func(t *testing.T) {
		listener, err := Listen("127.0.0.1:8887", []byte("dummy_cert"), []byte("dummy_key"))
		assert.NoError(t, err)
		t.Cleanup(func() {
			err := listener.Close()
			assert.NoError(t, err)
		})
		conn, err := listener.Accept()
		assert.NoError(t, err)
		assert.NotNil(t, conn)
	})
}
