// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package eat

import (
	"encoding/binary"
	"fmt"

	"github.com/google/go-sev-guest/abi"
	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
)

// OEMID constants (Private Enterprise Numbers)
const (
	OEMID_AMD       = 3704 // https://www.iana.org/assignments/enterprise-numbers/?q=Advanced+Micro+Devices
	OEMID_INTEL     = 343  // https://www.iana.org/assignments/enterprise-numbers/?q=Intel+Corporation
	OEMID_MICROSOFT = 311  // https://www.iana.org/assignments/enterprise-numbers/?q=Microsoft+Corporation
)

// extractSNPClaims extracts AMD SEV-SNP specific claims from binary report.
func extractSNPClaims(claims *EATClaims, report []byte) error {
	if len(report) < int(abi.ReportSize) {
		return fmt.Errorf("SNP report too small: got %d bytes, want at least %d", len(report), abi.ReportSize)
	}

	// Parse SNP report structure
	snpReport, err := abi.ReportToProto(report[:abi.ReportSize])
	if err != nil {
		return fmt.Errorf("failed to parse SNP report: %w", err)
	}

	// Extract SNP-specific fields
	claims.SNPExtensions = &SNPExtensions{
		Measurement:   snpReport.Measurement,
		Policy:        snpReport.Policy,
		FamilyID:      snpReport.FamilyId,
		ImageID:       snpReport.ImageId,
		VMPL:          int(snpReport.Vmpl),
		SignatureAlgo: int(snpReport.SignatureAlgo),
		PlatformInfo:  snpReport.PlatformInfo,
		ChipID:        snpReport.ChipId,
	}

	// Set TCB version info
	claims.SNPExtensions.CurrentTCB = snpReport.CurrentTcb
	claims.SNPExtensions.ReportedTCB = snpReport.ReportedTcb
	claims.SNPExtensions.CommittedTCB = snpReport.CommittedTcb
	claims.SNPExtensions.LaunchTCB = snpReport.LaunchTcb
	claims.SNPExtensions.TCB = fmt.Sprintf("current:%d,reported:%d", snpReport.CurrentTcb, snpReport.ReportedTcb)

	// Set core EAT claims from SNP report
	claims.Measurements = snpReport.Measurement
	claims.UEID = snpReport.ChipId // Use ChipID as UEID
	claims.OEMID = OEMID_AMD       // AMD's PEN (Private Enterprise Number)
	claims.SNPExtensions.Signature = snpReport.Signature

	// Set hardware model (hash of product name)
	claims.HWModel = []byte(fmt.Sprintf("SEV-SNP-%d", snpReport.Version))

	return nil
}

// extractTDXClaims extracts Intel TDX specific claims from binary report.
func extractTDXClaims(claims *EATClaims, report []byte) error {
	// Parse TDX quote using go-tdx-guest ABI
	decodedQuote, err := tdxabi.QuoteToProto(report)
	if err != nil {
		return fmt.Errorf("failed to parse TDX quote: %w", err)
	}

	quoteV4, ok := decodedQuote.(*tdxpb.QuoteV4)
	if !ok {
		return fmt.Errorf("unsupported TDX quote format")
	}

	tdReport := quoteV4.GetTdQuoteBody()
	signedData := quoteV4.GetSignedData()

	claims.TDXExtensions = &TDXExtensions{
		MRTD:          tdReport.GetMrTd(),
		RTMR:          tdReport.GetRtmrs(),
		XFAM:          binary.LittleEndian.Uint64(tdReport.GetXfam()),
		TDAttributes:  binary.LittleEndian.Uint64(tdReport.GetTdAttributes()),
		MRConfigID:    tdReport.GetMrConfigId(),
		MROwner:       tdReport.GetMrOwner(),
		MROwnerConfig: tdReport.GetMrOwnerConfig(),
		MRSEAM:        tdReport.GetMrSeam(),
		Signature:     signedData.GetSignature(),
	}

	// Set core EAT claims
	claims.Measurements = tdReport.GetMrTd()
	// Use first 32 bytes of MRTD as UEID, similar to other extractors
	if len(claims.Measurements) >= 32 {
		claims.UEID = claims.Measurements[:32]
	}
	claims.OEMID = OEMID_INTEL // Intel's PEN

	// Set hardware model
	claims.HWModel = []byte("Intel-TDX")

	return nil
}

// extractVTPMClaims extracts vTPM specific claims from binary report.
func extractVTPMClaims(claims *EATClaims, report []byte) error {
	// vTPM report is typically a marshaled structure containing PCRs and quote
	// For now, store the entire report as the quote
	claims.VTPMExtensions = &VTPMExtensions{
		Quote: report,
		PCRs:  make(map[string]string),
	}

	// Set core EAT claims
	claims.Measurements = report[:32] // Use first 32 bytes as measurement
	claims.UEID = report[:16]         // Use first 16 bytes as UEID

	return nil
}

// extractAzureClaims extracts Azure-specific claims from attestation token.
func extractAzureClaims(claims *EATClaims, report []byte) error {
	// Azure provides JWT tokens, so the report is already in a structured format
	// For now, just store it as raw report
	claims.Measurements = report[:32] // Use first 32 bytes as measurement
	claims.UEID = report[:16]         // Use first 16 bytes as UEID
	claims.OEMID = OEMID_MICROSOFT    // Microsoft's PEN

	return nil
}
