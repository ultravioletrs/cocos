// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"testing"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/ultravioletrs/cocos/pkg/clients/grpc"
)

func TestNewManagerClient(t *testing.T) {
	tests := []struct {
		name string
		cfg  grpc.Config
		err  error
	}{
		{
			name: "Valid config",
			cfg: grpc.Config{
				URL: "localhost:7001",
			},
			err: nil,
		},
		{
			name: "invalid config, missing BackendInfo with aTLS",
			cfg:  grpc.Config{AttestedTLS: true},
			err:  grpc.ErrBackendInfoMissing,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := NewManagerClient(tt.cfg)
			assert.True(t, errors.Contains(err, tt.err))
		})
	}
}
