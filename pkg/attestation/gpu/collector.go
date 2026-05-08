// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package gpu

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const (
	DefaultVendor         = "nvidia"
	DefaultEvidenceFormat = "nvat-json"
)

// Collector retrieves GPU evidence for the current attestation session.
type Collector interface {
	Collect(ctx context.Context, nonce []byte) (*Evidence, error)
}

// Evidence contains low-level GPU evidence collected out-of-process.
type Evidence struct {
	Vendor         string
	EvidenceFormat string
	Nonce          []byte
	RawEvidence    []byte
}

type commandCollector struct {
	binaryPath         string
	timeout            time.Duration
	execCommandContext func(ctx context.Context, name string, arg ...string) *exec.Cmd
}

type helperRequest struct {
	Mode         string          `json:"mode,omitempty"`
	NonceHex     string          `json:"nonce_hex"`
	EvidenceJSON json.RawMessage `json:"evidence_json,omitempty"`
}

type helperResponse struct {
	Vendor          string          `json:"vendor,omitempty"`
	EvidenceFormat  string          `json:"evidence_format,omitempty"`
	EvidenceJSON    json.RawMessage `json:"evidence_json,omitempty"`
	ClaimsJSON      json.RawMessage `json:"claims_json,omitempty"`
	DetachedEATJSON json.RawMessage `json:"detached_eat_json,omitempty"`
}

// NewCommandCollector creates a collector that shells out to a helper binary.
// The helper is expected to read a JSON request on stdin and emit a JSON
// response on stdout. See tools/nvidia-attestation-helper for the contract.
func NewCommandCollector(binaryPath string, timeout time.Duration) (Collector, error) {
	if strings.TrimSpace(binaryPath) == "" {
		return nil, fmt.Errorf("gpu helper path cannot be empty")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	return &commandCollector{
		binaryPath:         binaryPath,
		timeout:            timeout,
		execCommandContext: exec.CommandContext,
	}, nil
}

func (c *commandCollector) Collect(ctx context.Context, nonce []byte) (*Evidence, error) {
	if len(nonce) == 0 {
		return nil, fmt.Errorf("gpu nonce cannot be empty")
	}

	reqBody, err := json.Marshal(helperRequest{
		Mode:     "collect",
		NonceHex: hex.EncodeToString(nonce),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal GPU helper request: %w", err)
	}

	runCtx := ctx
	cancel := func() {}
	if c.timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, c.timeout)
	}
	defer cancel()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	cmd := c.execCommandContext(runCtx, c.binaryPath)
	cmd.Stdin = bytes.NewReader(reqBody)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Run(); err != nil {
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg == "" {
			errMsg = err.Error()
		}
		return nil, fmt.Errorf("gpu helper failed: %s", errMsg)
	}

	var resp helperResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return nil, fmt.Errorf("failed to decode GPU helper response: %w", err)
	}
	if len(resp.EvidenceJSON) == 0 {
		return nil, fmt.Errorf("gpu helper response did not contain evidence_json")
	}

	vendor := resp.Vendor
	if vendor == "" {
		vendor = DefaultVendor
	}

	evidenceFormat := resp.EvidenceFormat
	if evidenceFormat == "" {
		evidenceFormat = DefaultEvidenceFormat
	}

	return &Evidence{
		Vendor:         vendor,
		EvidenceFormat: evidenceFormat,
		Nonce:          append([]byte(nil), nonce...),
		RawEvidence:    append([]byte(nil), resp.EvidenceJSON...),
	}, nil
}

// SetExecCommandContext allows tests to inject a mock exec.CommandContext.
func (c *commandCollector) SetExecCommandContext(cmdFunc func(ctx context.Context, name string, arg ...string) *exec.Cmd) {
	c.execCommandContext = cmdFunc
}
