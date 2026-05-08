// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"

	attestationpb "github.com/ultravioletrs/cocos/internal/proto/attestation/v1"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/eat"
	attestationgpu "github.com/ultravioletrs/cocos/pkg/attestation/gpu"
)

func newGPUCollector(cfg config) (attestationgpu.Collector, error) {
	if strings.TrimSpace(cfg.GPUHelperPath) == "" {
		return nil, nil
	}

	return attestationgpu.NewCommandCollector(cfg.GPUHelperPath, cfg.GPUHelperTimeout)
}

func (s *service) claimOptions(ctx context.Context, req *attestationpb.AttestationRequest, platformType attestation.PlatformType) ([]eat.ClaimsOption, error) {
	var opts []eat.ClaimsOption

	if s.gpuCollector != nil && shouldCollectGPU(platformType) {
		sessionNonce := requestNonce(req)
		gpuNonce := deriveComponentNonce(sessionNonce, "gpu")

		evidence, err := s.gpuCollector.Collect(ctx, gpuNonce)
		if err != nil {
			// GPU evidence is opportunistic: if no supported CC-capable GPU is
			// attached, or the helper cannot collect evidence, we continue with
			// the root CPU/TEE attestation instead of failing the whole request.
			s.logger.Warn(fmt.Sprintf("[ATTESTATION-SERVICE] Skipping optional GPU evidence collection: %s", err))
			return opts, nil
		}

		s.logger.Info(fmt.Sprintf("[ATTESTATION-SERVICE] Collected GPU evidence: format=%s bytes=%d",
			evidence.EvidenceFormat, len(evidence.RawEvidence)))

		opts = append(opts, eat.WithGPU(&eat.GPUExtensions{
			Vendor:         evidence.Vendor,
			EvidenceFormat: evidence.EvidenceFormat,
			Nonce:          gpuNonce,
			EvidenceJSON:   evidence.RawEvidence,
		}))
	}

	return opts, nil
}

func shouldCollectGPU(platformType attestation.PlatformType) bool {
	switch platformType {
	case attestation.SNP, attestation.SNPvTPM, attestation.TDX, attestation.Azure:
		return true
	default:
		return false
	}
}

func requestNonce(req *attestationpb.AttestationRequest) []byte {
	if len(req.Nonce) > 0 {
		return append([]byte(nil), req.Nonce...)
	}

	return append([]byte(nil), req.ReportData...)
}

func deriveComponentNonce(sessionNonce []byte, component string) []byte {
	digest := sha256.Sum256(append(append([]byte(nil), sessionNonce...), []byte(":"+component)...))
	return digest[:]
}
