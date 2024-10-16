// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"testing"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/ultravioletrs/cocos/pkg/clients/grpc"
)

func TestNewAgentClient(t *testing.T) {
	tests := []struct {
		name string
		cfg  grpc.Config
		err  error
	}{
		{
			name: "Valid config",
			cfg:  grpc.Config{},
			err:  nil,
		},
		{
			name: "Invalid config",
			cfg:  grpc.Config{AttestedTLS: true},
			err:  grpc.ErrBackendInfoMissing,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := NewAgentClient(tt.cfg)
			assert.True(t, errors.Contains(err, tt.err))
		})
	}
}
