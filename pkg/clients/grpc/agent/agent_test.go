// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"testing"

	"github.com/ultravioletrs/cocos/pkg/clients/grpc"
)

func TestNewAgentClient(t *testing.T) {
	// Test cases
	tests := []struct {
		name    string
		cfg     grpc.Config
		wantErr bool
	}{
		{
			name:    "Valid config",
			cfg:     grpc.Config{},
			wantErr: false,
		},
		{
			name:    "Invalid config",
			cfg:     grpc.Config{AttestedTLS: true},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := NewAgentClient(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAgentClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
