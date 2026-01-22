// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
		s.logger.Warn("generating sample attestation for PLATFORM_TYPE_UNSPECIFIED - this should only be used for testing")
		s.logger.Info(fmt.Sprintf("[ATTESTATION-SERVICE] Generating sample attestation: reportData_len=%d, nonce_len=%d",
			len(req.ReportData), len(req.Nonce)))

		var reportData [64]byte
		copy(reportData[:], req.ReportData)

		// Create Sample Quote structure expected by KBS Sample Verifier
		// Must be JSON with "svn" and "report_data" (base64)
		type SampleQuote struct {
			Svn        string `json:"svn"`
			ReportData string `json:"report_data"`
		}

		quote := SampleQuote{
			Svn:        "1",
			ReportData: base64.StdEncoding.EncodeToString(reportData[:]),
		}

		binaryReport, err = json.Marshal(quote)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal sample quote: %w", err)
		}

		s.logger.Info(fmt.Sprintf("[ATTESTATION-SERVICE] Sample attestation generated: binaryReport_len=%d",
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
