// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package manager

import (
	"testing"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/ultravioletrs/cocos/pkg/clients/grpc"
)

func TestNewManagerClient(t *testing.T) {
	tests := []struct {
		name string
		cfg  grpc.ManagerClientConfig
		err  error
	}{
		{
			name: "Valid config",
			cfg: grpc.ManagerClientConfig{
				BaseConfig: grpc.BaseConfig{
					URL: "localhost:7001",
				},
			},
			err: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := NewManagerClient(tt.cfg)
			assert.True(t, errors.Contains(err, tt.err))
		})
	}
}
