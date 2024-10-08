// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"google.golang.org/grpc/metadata"
)

func TestDatasetsString(t *testing.T) {
	datasets := Datasets{
		{
			Hash:     [32]byte{1, 2, 3},
			UserKey:  []byte("user_key"),
			Filename: "test.dat",
		},
	}

	expected := `[{"hash":[1,2,3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"user_key":"dXNlcl9rZXk=","filename":"test.dat"}]`
	result := datasets.String()

	if result != expected {
		t.Errorf("Datasets.String() = %v, want %v", result, expected)
	}
}

func TestIndexToContext(t *testing.T) {
	ctx := context.Background()
	index := 5

	newCtx := IndexToContext(ctx, index)
	result, ok := IndexFromContext(newCtx)

	if !ok {
		t.Errorf("IndexFromContext() ok = false, want true")
	}

	if result != index {
		t.Errorf("IndexFromContext() = %v, want %v", result, index)
	}
}

func TestDecompressFromContext(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		expected bool
	}{
		{
			name:     "No decompress metadata",
			ctx:      context.Background(),
			expected: false,
		},
		{
			name: "Decompress true",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs(DecompressKey, "true"),
			),
			expected: true,
		},
		{
			name: "Decompress false",
			ctx: metadata.NewIncomingContext(
				context.Background(),
				metadata.Pairs(DecompressKey, "false"),
			),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DecompressFromContext(tt.ctx)
			if result != tt.expected {
				t.Errorf("DecompressFromContext() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestDecompressToContext(t *testing.T) {
	ctx := context.Background()
	decompress := true

	newCtx := DecompressToContext(ctx, decompress)
	md, ok := metadata.FromOutgoingContext(newCtx)

	if !ok {
		t.Errorf("metadata.FromOutgoingContext() ok = false, want true")
	}

	vals := md.Get(DecompressKey)
	if len(vals) != 1 {
		t.Errorf("len(md.Get(DecompressKey)) = %v, want 1", len(vals))
	}

	if vals[0] != "true" {
		t.Errorf("md.Get(DecompressKey)[0] = %v, want 'true'", vals[0])
	}
}

func TestAgentConfigJSON(t *testing.T) {
	config := AgentConfig{
		LogLevel:     "info",
		Host:         "localhost",
		Port:         "8080",
		CertFile:     "cert.pem",
		KeyFile:      "key.pem",
		ServerCAFile: "server_ca.pem",
		ClientCAFile: "client_ca.pem",
		AttestedTls:  true,
	}

	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Failed to marshal AgentConfig: %v", err)
	}

	var unmarshaledConfig AgentConfig
	err = json.Unmarshal(data, &unmarshaledConfig)
	if err != nil {
		t.Fatalf("Failed to unmarshal AgentConfig: %v", err)
	}

	if !reflect.DeepEqual(config, unmarshaledConfig) {
		t.Errorf("Unmarshaled config does not match original. Got %+v, want %+v", unmarshaledConfig, config)
	}
}
