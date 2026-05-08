// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package gpu

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fakeExecCommandContext(_ context.Context, name string, arg ...string) *exec.Cmd {
	args := append([]string{"-test.run=TestGPUHelperProcess", "--", name}, arg...)
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "GO_WANT_GPU_HELPER_PROCESS=1")
	return cmd
}

func TestGPUHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_GPU_HELPER_PROCESS") != "1" {
		return
	}

	args := os.Args
	for i := range args {
		if args[i] == "--" {
			args = args[i+1:]
			break
		}
	}

	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "missing helper name")
		os.Exit(2)
	}

	switch args[0] {
	case "helper-error":
		fmt.Fprintln(os.Stderr, "simulated helper failure")
		os.Exit(1)
	case "helper-invalid-json":
		fmt.Fprintln(os.Stdout, "{not-json")
		os.Exit(0)
	case "helper-empty-evidence":
		fmt.Fprintln(os.Stdout, `{"vendor":"nvidia","evidence_format":"nvat-json"}`)
		os.Exit(0)
	default:
		var req helperRequest
		if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		if req.Mode != "collect" {
			fmt.Fprintln(os.Stderr, "unexpected helper mode")
			os.Exit(1)
		}

		resp := helperResponse{
			Vendor:         "nvidia",
			EvidenceFormat: "nvat-json",
			EvidenceJSON:   json.RawMessage(fmt.Sprintf(`{"nonce_hex":"%s","evidence":"ok"}`, req.NonceHex)),
		}
		if err := json.NewEncoder(os.Stdout).Encode(resp); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}
}

func TestNewCommandCollector(t *testing.T) {
	collector, err := NewCommandCollector("helper", time.Second)
	assert.NoError(t, err)
	assert.NotNil(t, collector)

	collector, err = NewCommandCollector("", time.Second)
	assert.Error(t, err)
	assert.Nil(t, collector)
}

func TestCommandCollectorCollect(t *testing.T) {
	collector, err := NewCommandCollector("helper-success", time.Second)
	require.NoError(t, err)

	cmdCollector, ok := collector.(*commandCollector)
	require.True(t, ok)
	cmdCollector.SetExecCommandContext(fakeExecCommandContext)

	evidence, err := collector.Collect(context.Background(), []byte{0xaa, 0xbb, 0xcc})
	require.NoError(t, err)
	assert.Equal(t, DefaultVendor, evidence.Vendor)
	assert.Equal(t, DefaultEvidenceFormat, evidence.EvidenceFormat)
	assert.Equal(t, []byte{0xaa, 0xbb, 0xcc}, evidence.Nonce)
	assert.JSONEq(t, `{"nonce_hex":"aabbcc","evidence":"ok"}`, string(evidence.RawEvidence))
}

func TestCommandCollectorCollectErrors(t *testing.T) {
	tests := []struct {
		name       string
		helperName string
		wantErr    string
	}{
		{
			name:       "helper process failure",
			helperName: "helper-error",
			wantErr:    "gpu helper failed: simulated helper failure",
		},
		{
			name:       "invalid json response",
			helperName: "helper-invalid-json",
			wantErr:    "failed to decode GPU helper response",
		},
		{
			name:       "missing evidence payload",
			helperName: "helper-empty-evidence",
			wantErr:    "gpu helper response did not contain evidence_json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector, err := NewCommandCollector(tt.helperName, time.Second)
			require.NoError(t, err)

			cmdCollector, ok := collector.(*commandCollector)
			require.True(t, ok)
			cmdCollector.SetExecCommandContext(fakeExecCommandContext)

			_, err = collector.Collect(context.Background(), []byte{0xaa})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}
