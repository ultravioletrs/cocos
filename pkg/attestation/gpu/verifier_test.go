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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/corim"
)

// validClaimsJSON is a well-formed helper response matching the real SDK output
// (hopperClaimsv3_decoded.json from the NVAT SDK test data).
const validClaimsJSON = `{
	"GPU-0": {
		"hwmodel": "GH100 A01 GSP BROM",
		"oemid": "5703",
		"x-nvidia-gpu-driver-version": "550.90.07",
		"x-nvidia-gpu-vbios-version": "96.00.9F.00.01",
		"secboot": true,
		"dbgstat": "disabled",
		"measres": "success",
		"x-nvidia-gpu-attestation-report-nonce-match": true,
		"x-nvidia-gpu-attestation-report-signature-verified": true,
		"x-nvidia-gpu-attestation-report-cert-chain-fwid-match": true,
		"x-nvidia-gpu-arch-check": true,
		"x-nvidia-gpu-driver-rim-signature-verified": true,
		"x-nvidia-gpu-vbios-rim-signature-verified": true,
		"x-nvidia-gpu-driver-rim-version-match": true,
		"x-nvidia-gpu-vbios-rim-version-match": true,
		"x-nvidia-attestation-warning": null
	}
}`

func fakeVerifierExecCommandContext(_ context.Context, name string, arg ...string) *exec.Cmd {
	args := append([]string{"-test.run=TestGPUVerifierHelperProcess", "--", name}, arg...)
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), "GO_WANT_GPU_VERIFIER_PROCESS=1")
	return cmd
}

func TestGPUVerifierHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_GPU_VERIFIER_PROCESS") != "1" {
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
		fmt.Fprintln(os.Stderr, "missing verifier binary name")
		os.Exit(2)
	}

	switch args[0] {
	case "verifier-error":
		fmt.Fprintln(os.Stderr, "simulated verifier failure")
		os.Exit(1)
	case "verifier-invalid-json":
		fmt.Fprintln(os.Stdout, "{not-json")
		os.Exit(0)
	case "verifier-empty-claims":
		fmt.Fprintln(os.Stdout, `{"detached_eat_json":{"overall_result":true}}`)
		os.Exit(0)
	case "verifier-invalid-claims-format":
		fmt.Fprintln(os.Stdout, `{"claims_json":[1,2,3]}`)
		os.Exit(0)
	case "verifier-empty-device-claims":
		fmt.Fprintln(os.Stdout, `{"claims_json":{}}`)
		os.Exit(0)
	default:
		var req helperRequest
		if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		if req.Mode != "verify" {
			fmt.Fprintln(os.Stderr, "unexpected verifier mode")
			os.Exit(1)
		}
		if req.NonceHex == "" {
			fmt.Fprintln(os.Stderr, "nonce not propagated to verifier helper")
			os.Exit(1)
		}
		if !json.Valid(req.EvidenceJSON) {
			fmt.Fprintln(os.Stderr, "invalid evidence_json payload")
			os.Exit(1)
		}
		if !containsNonce(req.EvidenceJSON, req.NonceHex) {
			fmt.Fprintln(os.Stderr, "nonce not propagated to verifier")
			os.Exit(1)
		}

		resp := helperResponse{
			ClaimsJSON:      json.RawMessage(validClaimsJSON),
			DetachedEATJSON: json.RawMessage(`{"overall_result":true}`),
		}
		if err := json.NewEncoder(os.Stdout).Encode(resp); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}
}

func TestEvidenceNonce(t *testing.T) {
	nonce, err := evidenceNonce([]byte(`[{"nonce":"aabbcc"}]`))
	assert.NoError(t, err)
	assert.Equal(t, "aabbcc", nonce)

	_, err = evidenceNonce([]byte(`[]`))
	assert.ErrorContains(t, err, "did not contain any devices")

	_, err = evidenceNonce([]byte(`[{}]`))
	assert.ErrorContains(t, err, "nonce is missing")
}

func containsNonce(report json.RawMessage, nonce string) bool {
	var envelopes []evidenceEnvelope
	if err := json.Unmarshal(report, &envelopes); err != nil {
		return false
	}
	if len(envelopes) == 0 {
		return false
	}

	return envelopes[0].Nonce == nonce
}

func TestVerifierVerifyWithCoRIM(t *testing.T) {
	v, err := NewVerifier("verifier-success", 0)
	require.NoError(t, err)

	cmdVerifier, ok := v.(*verifier)
	require.True(t, ok)
	cmdVerifier.SetExecCommandContext(fakeVerifierExecCommandContext)

	report := []byte(`[{"nonce":"aabbcc","evidence":"abc","certificate":"def"}]`)

	// nil manifest: CoRIM phase skipped, only mandatory flags checked.
	err = v.VerifyWithCoRIM(report, nil)
	assert.NoError(t, err)

	// Empty manifest: no digest entries → matchesCoRIM returns true → pass.
	err = v.VerifyWithCoRIM(report, &corim.UnsignedCorim{})
	assert.NoError(t, err)
}

func TestVerifierVerifyWithCoRIMErrors(t *testing.T) {
	tests := []struct {
		name      string
		binary    string
		report    []byte
		wantError string
	}{
		{
			name:      "empty report",
			report:    nil,
			wantError: "gpu evidence is empty",
		},
		{
			name:      "invalid json",
			report:    []byte(`{`),
			wantError: "failed to parse GPU evidence JSON",
		},
		{
			name:      "helper failure",
			binary:    "verifier-error",
			report:    []byte(`[{"nonce":"aabbcc"}]`),
			wantError: "gpu verifier helper failed",
		},
		{
			name:      "invalid verifier response",
			binary:    "verifier-invalid-json",
			report:    []byte(`[{"nonce":"aabbcc"}]`),
			wantError: "failed to decode GPU verifier response",
		},
		{
			name:      "missing claims",
			binary:    "verifier-empty-claims",
			report:    []byte(`[{"nonce":"aabbcc"}]`),
			wantError: "gpu verifier response did not contain claims_json",
		},
		{
			name:      "invalid claims format",
			binary:    "verifier-invalid-claims-format",
			report:    []byte(`[{"nonce":"aabbcc"}]`),
			wantError: "gpu: failed to parse claims JSON",
		},
		{
			name:      "empty device claims",
			binary:    "verifier-empty-device-claims",
			report:    []byte(`[{"nonce":"aabbcc"}]`),
			wantError: "gpu: verifier response contained no device claims",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "empty report" || tt.name == "invalid json" {
				v, err := NewVerifier("verifier-success", 0)
				require.NoError(t, err)
				err = v.VerifyWithCoRIM(tt.report, nil)
				assert.ErrorContains(t, err, tt.wantError)
				return
			}

			v, err := NewVerifier(tt.binary, 0)
			require.NoError(t, err)

			cmdVerifier, ok := v.(*verifier)
			require.True(t, ok)
			cmdVerifier.SetExecCommandContext(fakeVerifierExecCommandContext)

			err = v.VerifyWithCoRIM(tt.report, nil)
			assert.ErrorContains(t, err, tt.wantError)
		})
	}
}

func TestAppraiseGPUClaims(t *testing.T) {
	warning := "some warning"
	validDevice := gpuDeviceClaims{
		HWModel:               "GH100 A01 GSP BROM",
		OEMID:                 "5703",
		DriverVersion:         "550.90.07",
		VBIOSVersion:          "96.00.9F.00.01",
		SecBoot:               true,
		DebugStatus:           "disabled",
		MeasurementResult:     "success",
		NonceMatch:            true,
		SigVerified:           true,
		FWIDMatch:             true,
		ArchCheck:             true,
		DriverRIMSigVerified:  true,
		VBIOSRIMSigVerified:   true,
		DriverRIMVersionMatch: true,
		VBIOSRIMVersionMatch:  true,
		AttestationWarning:    nil,
	}

	tests := []struct {
		name      string
		modify    func(gpuDeviceClaims) gpuDeviceClaims
		wantError string
	}{
		{
			name:   "all valid",
			modify: func(c gpuDeviceClaims) gpuDeviceClaims { return c },
		},
		{
			name:      "secure boot disabled",
			modify:    func(c gpuDeviceClaims) gpuDeviceClaims { c.SecBoot = false; return c },
			wantError: "secure boot not enabled",
		},
		{
			name:      "debug not disabled",
			modify:    func(c gpuDeviceClaims) gpuDeviceClaims { c.DebugStatus = "enabled"; return c },
			wantError: "debug not disabled",
		},
		{
			name:      "measurement result failed",
			modify:    func(c gpuDeviceClaims) gpuDeviceClaims { c.MeasurementResult = "failed"; return c },
			wantError: "measurement result not success",
		},
		{
			name:      "nonce mismatch",
			modify:    func(c gpuDeviceClaims) gpuDeviceClaims { c.NonceMatch = false; return c },
			wantError: "one or more attestation verification flags are false",
		},
		{
			name:      "signature not verified",
			modify:    func(c gpuDeviceClaims) gpuDeviceClaims { c.SigVerified = false; return c },
			wantError: "one or more attestation verification flags are false",
		},
		{
			name:      "fwid mismatch",
			modify:    func(c gpuDeviceClaims) gpuDeviceClaims { c.FWIDMatch = false; return c },
			wantError: "one or more attestation verification flags are false",
		},
		{
			name:      "arch check failed",
			modify:    func(c gpuDeviceClaims) gpuDeviceClaims { c.ArchCheck = false; return c },
			wantError: "one or more attestation verification flags are false",
		},
		{
			name:      "driver RIM sig not verified",
			modify:    func(c gpuDeviceClaims) gpuDeviceClaims { c.DriverRIMSigVerified = false; return c },
			wantError: "one or more attestation verification flags are false",
		},
		{
			name:      "vbios RIM sig not verified",
			modify:    func(c gpuDeviceClaims) gpuDeviceClaims { c.VBIOSRIMSigVerified = false; return c },
			wantError: "one or more attestation verification flags are false",
		},
		{
			name:      "driver RIM version mismatch",
			modify:    func(c gpuDeviceClaims) gpuDeviceClaims { c.DriverRIMVersionMatch = false; return c },
			wantError: "one or more attestation verification flags are false",
		},
		{
			name:      "vbios RIM version mismatch",
			modify:    func(c gpuDeviceClaims) gpuDeviceClaims { c.VBIOSRIMVersionMatch = false; return c },
			wantError: "one or more attestation verification flags are false",
		},
		{
			name:      "attestation warning present",
			modify:    func(c gpuDeviceClaims) gpuDeviceClaims { c.AttestationWarning = &warning; return c },
			wantError: "attestation warning",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			devices := map[string]gpuDeviceClaims{
				"GPU-0": tt.modify(validDevice),
			}
			err := appraiseGPUClaims(devices, nil)
			if tt.wantError == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.wantError)
			}
		})
	}
}

func TestMatchesCoRIM(t *testing.T) {
	digest := []byte("some-32-byte-digest-padding-here")

	t.Run("nil tags returns true", func(t *testing.T) {
		assert.True(t, matchesCoRIM(digest, &corim.UnsignedCorim{}))
	})

	t.Run("non-ComidTag prefix is skipped", func(t *testing.T) {
		m := &corim.UnsignedCorim{
			Tags: []corim.Tag{[]byte{0x01, 0x02, 0x03}},
		}
		assert.True(t, matchesCoRIM(digest, m))
	})

	t.Run("unparseable ComidTag payload is skipped", func(t *testing.T) {
		bad := append(append([]byte{}, corim.ComidTag...), 0xFF, 0xFE)
		m := &corim.UnsignedCorim{Tags: []corim.Tag{bad}}
		assert.True(t, matchesCoRIM(digest, m))
	})
}
