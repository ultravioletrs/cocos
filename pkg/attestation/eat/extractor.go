// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package eat

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/google/go-sev-guest/abi"
	sevsnppb "github.com/google/go-sev-guest/proto/sevsnp"
	tdxabi "github.com/google/go-tdx-guest/abi"
	tdxpb "github.com/google/go-tdx-guest/proto/tdx"
	attestpb "github.com/google/go-tpm-tools/proto/attest"
	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
	"google.golang.org/protobuf/proto"
)

// OEMID constants (Private Enterprise Numbers).
const (
	OEMID_AMD       = 3704 // https://www.iana.org/assignments/enterprise-numbers/?q=Advanced+Micro+Devices
	OEMID_INTEL     = 343  // https://www.iana.org/assignments/enterprise-numbers/?q=Intel+Corporation
	OEMID_MICROSOFT = 311  // https://www.iana.org/assignments/enterprise-numbers/?q=Microsoft+Corporation
)

// extractSNPClaims extracts AMD SEV-SNP specific claims from binary report.
// report may be one of three formats:
//  1. proto-marshaled sevsnp.Attestation (SNP-only platform, from fetchSEVAttestation)
//  2. proto-marshaled attest.Attestation (go-tpm-tools, SNP_VTPM platform, field 7 = SevSnpAttestation)
//  3. raw binary SNP report (0x4A0 bytes)
func extractSNPClaims(claims *EATClaims, report []byte) error {
	// Try sevsnp.Attestation (SNP-only proto format).
	var sevAttest sevsnppb.Attestation
	if err := proto.Unmarshal(report, &sevAttest); err == nil {
		if r := sevAttest.GetReport(); r != nil {
			return populateSNPClaims(claims, r)
		}
	}

	// Try attest.Attestation (go-tpm-tools SNP_VTPM format).
	var tpmAttest attestpb.Attestation
	if err := proto.Unmarshal(report, &tpmAttest); err == nil {
		if snp := tpmAttest.GetSevSnpAttestation(); snp != nil {
			if r := snp.GetReport(); r != nil {
				if err := populateSNPClaims(claims, r); err != nil {
					return err
				}
				populateVTPMClaims(claims, tpmAttest.GetQuotes(), tpmAttest.GetEventLog())
				return nil
			}
		}
	}

	// Fall back to raw binary SNP report.
	if len(report) < int(abi.ReportSize) {
		return fmt.Errorf("SNP report too small: got %d bytes, want at least %d", len(report), abi.ReportSize)
	}
	snpReport, err := abi.ReportToProto(report[:abi.ReportSize])
	if err != nil {
		return fmt.Errorf("failed to parse SNP report: %w", err)
	}
	return populateSNPClaims(claims, snpReport)
}

func populateSNPClaims(claims *EATClaims, snpReport *sevsnppb.Report) error {
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
	claims.SNPExtensions.CurrentTCB = snpReport.CurrentTcb
	claims.SNPExtensions.ReportedTCB = snpReport.ReportedTcb
	claims.SNPExtensions.CommittedTCB = snpReport.CommittedTcb
	claims.SNPExtensions.LaunchTCB = snpReport.LaunchTcb
	claims.SNPExtensions.TCB = fmt.Sprintf("current:%d,reported:%d", snpReport.CurrentTcb, snpReport.ReportedTcb)
	claims.SNPExtensions.Signature = snpReport.Signature
	claims.Measurements = snpReport.Measurement
	claims.UEID = snpReport.ChipId
	claims.OEMID = OEMID_AMD
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

	rtmrs := tdReport.GetRtmrs()
	var rtmr0, rtmr1, rtmr2, rtmr3 []byte
	if len(rtmrs) > 0 {
		rtmr0 = rtmrs[0]
	}
	if len(rtmrs) > 1 {
		rtmr1 = rtmrs[1]
	}
	if len(rtmrs) > 2 {
		rtmr2 = rtmrs[2]
	}
	if len(rtmrs) > 3 {
		rtmr3 = rtmrs[3]
	}

	claims.TDXExtensions = &TDXExtensions{
		MRTD:          tdReport.GetMrTd(),
		RTMR0:         rtmr0,
		RTMR1:         rtmr1,
		RTMR2:         rtmr2,
		RTMR3:         rtmr3,
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

// populateVTPMClaims fills VTPMExtensions from go-tpm-tools quote banks and event log.
// For SNP_VTPM the SNP measurement is already set; this adds PCR values alongside it.
// PCR keys are formatted as "<hash>:<index>" (e.g. "sha256:0"), values are hex-encoded.
// The raw TPMS_ATTEST bytes from the SHA-256 bank are stored as the canonical Quote.
func populateVTPMClaims(claims *EATClaims, quotes []*tpmpb.Quote, eventLog []byte) {
	vtpm := &VTPMExtensions{
		PCRs:     make(map[string]string),
		EventLog: eventLog,
	}

	for _, q := range quotes {
		if q == nil {
			continue
		}
		pcrs := q.GetPcrs()
		if pcrs == nil {
			continue
		}

		// Prefer the SHA-256 bank as the canonical raw quote; fall back to the first available.
		if pcrs.GetHash() == tpmpb.HashAlgo_SHA256 || vtpm.Quote == nil {
			if raw := q.GetQuote(); len(raw) > 0 {
				vtpm.Quote = raw
			}
		}

		hashName := tpmHashName(pcrs.GetHash())
		for idx, val := range pcrs.GetPcrs() {
			vtpm.PCRs[fmt.Sprintf("%s:%d", hashName, idx)] = hex.EncodeToString(val)
		}
	}

	claims.VTPMExtensions = vtpm
}

func tpmHashName(h tpmpb.HashAlgo) string {
	switch h {
	case tpmpb.HashAlgo_SHA1:
		return "sha1"
	case tpmpb.HashAlgo_SHA256:
		return "sha256"
	case tpmpb.HashAlgo_SHA384:
		return "sha384"
	case tpmpb.HashAlgo_SHA512:
		return "sha512"
	default:
		return fmt.Sprintf("hash%d", int(h))
	}
}

// extractVTPMClaims extracts vTPM specific claims from a proto-marshaled attest.Attestation.
func extractVTPMClaims(claims *EATClaims, report []byte) error {
	var tpmAttest attestpb.Attestation
	if err := proto.Unmarshal(report, &tpmAttest); err != nil {
		return fmt.Errorf("failed to parse vTPM attestation: %w", err)
	}

	populateVTPMClaims(claims, tpmAttest.GetQuotes(), tpmAttest.GetEventLog())

	// Use PCR0 (SHA-256) as the canonical measurement if present.
	if ext := claims.VTPMExtensions; ext != nil {
		if v, ok := ext.PCRs["sha256:0"]; ok {
			b, err := hex.DecodeString(v)
			if err == nil {
				claims.Measurements = b
				if len(b) >= 16 {
					claims.UEID = b[:16]
				}
			}
		}
	}

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
