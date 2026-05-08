// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package gpu

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
)

const (
	DefaultVerifierBinary  = "nvidia-attestation-helper"
	defaultVerifierTimeout = 30 * time.Second
)

var _ attestation.Verifier = (*verifier)(nil)

type verifier struct {
	binaryPath         string
	timeout            time.Duration
	execCommandContext func(ctx context.Context, name string, arg ...string) *exec.Cmd
}

type evidenceEnvelope struct {
	Nonce string `json:"nonce"`
}

// gpuDeviceClaims mirrors the per-device object produced by the NVIDIA
// attestation helper's verify mode (e.g. "GPU-0": { ... }).
type gpuDeviceClaims struct {
	HWModel               string  `json:"hwmodel"`
	OEMID                 string  `json:"oemid"`
	DriverVersion         string  `json:"x-nvidia-gpu-driver-version"`
	VBIOSVersion          string  `json:"x-nvidia-gpu-vbios-version"`
	SecBoot               bool    `json:"secboot"`
	DebugStatus           string  `json:"dbgstat"`
	MeasurementResult     string  `json:"measres"`
	NonceMatch            bool    `json:"x-nvidia-gpu-attestation-report-nonce-match"`
	SigVerified           bool    `json:"x-nvidia-gpu-attestation-report-signature-verified"`
	FWIDMatch             bool    `json:"x-nvidia-gpu-attestation-report-cert-chain-fwid-match"`
	ArchCheck             bool    `json:"x-nvidia-gpu-arch-check"`
	DriverRIMSigVerified  bool    `json:"x-nvidia-gpu-driver-rim-signature-verified"`
	VBIOSRIMSigVerified   bool    `json:"x-nvidia-gpu-vbios-rim-signature-verified"`
	DriverRIMVersionMatch bool    `json:"x-nvidia-gpu-driver-rim-version-match"`
	VBIOSRIMVersionMatch  bool    `json:"x-nvidia-gpu-vbios-rim-version-match"`
	AttestationWarning    *string `json:"x-nvidia-attestation-warning"`
}

func NewVerifier(binaryPath string, timeout time.Duration) (attestation.Verifier, error) {
	if strings.TrimSpace(binaryPath) == "" {
		binaryPath = DefaultVerifierBinary
	}
	if timeout <= 0 {
		timeout = defaultVerifierTimeout
	}

	return &verifier{
		binaryPath:         binaryPath,
		timeout:            timeout,
		execCommandContext: exec.CommandContext,
	}, nil
}

func (v *verifier) VerifyWithCoRIM(report []byte, manifest *corim.UnsignedCorim) error {
	if len(report) == 0 {
		return fmt.Errorf("gpu evidence is empty")
	}

	nonceHex, err := evidenceNonce(report)
	if err != nil {
		return err
	}

	reqBody, err := json.Marshal(helperRequest{
		Mode:         "verify",
		NonceHex:     nonceHex,
		EvidenceJSON: append(json.RawMessage(nil), report...),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal GPU verifier request: %w", err)
	}

	runCtx := context.Background()
	cancel := func() {}
	if v.timeout > 0 {
		runCtx, cancel = context.WithTimeout(runCtx, v.timeout)
	}
	defer cancel()

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	cmd := v.execCommandContext(runCtx, v.binaryPath)
	cmd.Stdin = bytes.NewReader(reqBody)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Run(); err != nil {
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg == "" {
			errMsg = err.Error()
		}
		return fmt.Errorf("gpu verifier helper failed: %s", errMsg)
	}

	var resp helperResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return fmt.Errorf("failed to decode GPU verifier response: %w", err)
	}
	if len(resp.ClaimsJSON) == 0 {
		return fmt.Errorf("gpu verifier response did not contain claims_json")
	}

	var deviceClaims map[string]gpuDeviceClaims
	if err := json.Unmarshal(resp.ClaimsJSON, &deviceClaims); err != nil {
		return fmt.Errorf("gpu: failed to parse claims JSON: %w", err)
	}
	if len(deviceClaims) == 0 {
		return fmt.Errorf("gpu: verifier response contained no device claims")
	}

	return appraiseGPUClaims(deviceClaims, manifest)
}

// appraiseGPUClaims checks mandatory security flags on every device, then
// matches each device's identity against CoRIM reference values when a
// manifest is provided.
func appraiseGPUClaims(devices map[string]gpuDeviceClaims, manifest *corim.UnsignedCorim) error {
	for id, c := range devices {
		if !c.SecBoot {
			return fmt.Errorf("gpu: %s: secure boot not enabled", id)
		}
		if c.DebugStatus != "disabled" {
			return fmt.Errorf("gpu: %s: debug not disabled (got %q)", id, c.DebugStatus)
		}
		if c.MeasurementResult != "success" {
			return fmt.Errorf("gpu: %s: measurement result not success (got %q)", id, c.MeasurementResult)
		}
		if !c.NonceMatch || !c.SigVerified || !c.FWIDMatch || !c.ArchCheck ||
			!c.DriverRIMSigVerified || !c.VBIOSRIMSigVerified ||
			!c.DriverRIMVersionMatch || !c.VBIOSRIMVersionMatch {
			return fmt.Errorf("gpu: %s: one or more attestation verification flags are false", id)
		}
		if c.AttestationWarning != nil {
			return fmt.Errorf("gpu: %s: attestation warning: %s", id, *c.AttestationWarning)
		}
	}

	if manifest == nil {
		return nil
	}

	// Match each device's identity (model|driver|vbios) against CoRIM digests.
	// matchesCoRIM returns true when a digest matches OR when the manifest
	// contains no digest entries at all (no GPU policy configured).
	for id, c := range devices {
		identity := c.HWModel + "|" + c.DriverVersion + "|" + c.VBIOSVersion
		digest := sha256.Sum256([]byte(identity))
		if !matchesCoRIM(digest[:], manifest) {
			return fmt.Errorf("gpu: %s: no CoRIM reference value matched (model=%q driver=%q vbios=%q)",
				id, c.HWModel, c.DriverVersion, c.VBIOSVersion)
		}
	}
	return nil
}

// matchesCoRIM returns true when digest matches any reference value digest in
// the manifest, or when the manifest contains no digest entries (treating an
// empty manifest as "no GPU policy configured").
func matchesCoRIM(digest []byte, manifest *corim.UnsignedCorim) bool {
	hasAnyDigests := false
	for _, tag := range manifest.Tags {
		if !bytes.HasPrefix(tag, corim.ComidTag) {
			continue
		}
		var c comid.Comid
		if err := c.FromCBOR(tag[len(corim.ComidTag):]); err != nil {
			continue
		}
		if c.Triples.ReferenceValues == nil {
			continue
		}
		for _, rv := range *c.Triples.ReferenceValues {
			if rv.Measurements.Valid() != nil {
				continue
			}
			for _, m := range rv.Measurements {
				if m.Val.Digests == nil {
					continue
				}
				for _, d := range *m.Val.Digests {
					hasAnyDigests = true
					if bytes.Equal(d.HashValue, digest) {
						return true
					}
				}
			}
		}
	}
	return !hasAnyDigests
}

func evidenceNonce(report []byte) (string, error) {
	var envelopes []evidenceEnvelope
	if err := json.Unmarshal(report, &envelopes); err != nil {
		return "", fmt.Errorf("failed to parse GPU evidence JSON: %w", err)
	}
	if len(envelopes) == 0 {
		return "", fmt.Errorf("gpu evidence did not contain any devices")
	}
	if strings.TrimSpace(envelopes[0].Nonce) == "" {
		return "", fmt.Errorf("gpu evidence nonce is missing")
	}

	return envelopes[0].Nonce, nil
}

// SetExecCommandContext allows tests to inject a mock exec.CommandContext.
func (v *verifier) SetExecCommandContext(cmdFunc func(ctx context.Context, name string, arg ...string) *exec.Cmd) {
	v.execCommandContext = cmdFunc
}
