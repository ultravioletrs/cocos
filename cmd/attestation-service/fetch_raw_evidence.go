// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"fmt"

	attestationpb "github.com/ultravioletrs/cocos/internal/proto/attestation/v1"
)

func (s *service) FetchRawEvidence(ctx context.Context, req *attestationpb.AttestationRequest) (*attestationpb.RawEvidenceResponse, error) {
	s.logger.Info(fmt.Sprintf("[ATTESTATION-SERVICE] Received raw evidence request with platform type: %v (%d)",
		req.PlatformType, req.PlatformType))

	var binaryReport []byte
	var err error

	// Get binary attestation report based on platform type
	switch req.PlatformType {
	case attestationpb.PlatformType_PLATFORM_TYPE_SNP, attestationpb.PlatformType_PLATFORM_TYPE_TDX:
		var reportData [64]byte
		copy(reportData[:], req.ReportData)
		binaryReport, err = s.provider.TeeAttestation(reportData[:])
	case attestationpb.PlatformType_PLATFORM_TYPE_VTPM:
		var nonce [32]byte
		copy(nonce[:], req.Nonce)
		binaryReport, err = s.provider.VTpmAttestation(nonce[:])
	case attestationpb.PlatformType_PLATFORM_TYPE_SNP_VTPM:
		var reportData [64]byte
		copy(reportData[:], req.ReportData)
		var nonce [32]byte
		copy(nonce[:], req.Nonce)
		binaryReport, err = s.provider.Attestation(reportData[:], nonce[:])
	case attestationpb.PlatformType_PLATFORM_TYPE_UNSPECIFIED:
		// Generate sample attestation for testing in non-TEE environments
		// This uses the underlying provider (EmptyProvider or CC Attestation Agent)
		s.logger.Warn("fetching sample attestation for PLATFORM_TYPE_UNSPECIFIED")
		s.logger.Info(fmt.Sprintf("[ATTESTATION-SERVICE] Fetching sample/unspecified attestation: reportData_len=%d",
			len(req.ReportData)))

		// Use TeeAttestation interface - for EmptyProvider this generates dynamic JSON sample quote
		// For CC AA, this calls the agent to get a real quote (if supported)
		var reportData [64]byte
		copy(reportData[:], req.ReportData)
		binaryReport, err = s.provider.TeeAttestation(reportData[:])
		if err != nil {
			return nil, fmt.Errorf("failed to fetch sample attestation: %w", err)
		}

		s.logger.Info(fmt.Sprintf("[ATTESTATION-SERVICE] Sample attestation fetched: binaryReport_len=%d",
			len(binaryReport)))
	default:
		return nil, fmt.Errorf("unsupported platform type")
	}

	if err != nil {
		return nil, err
	}

	s.logger.Info(fmt.Sprintf("[ATTESTATION-SERVICE] Returning raw evidence: len=%d", len(binaryReport)))

	return &attestationpb.RawEvidenceResponse{Evidence: binaryReport}, nil
}
