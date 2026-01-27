// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package eat

import (
	"errors"

	"github.com/ultravioletrs/cocos/pkg/attestation"
)

// EATClaims represents the Entity Attestation Token claims following RFC 9711.
type EATClaims struct {
	// Standard JWT/CWT claims
	Issuer    string `json:"iss,omitempty" cbor:"1,keyasint,omitempty"`
	Subject   string `json:"sub,omitempty" cbor:"2,keyasint,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty" cbor:"6,keyasint,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty" cbor:"4,keyasint,omitempty"`

	// Core EAT claims (RFC 9711)
	Nonce        []byte `json:"eat_nonce" cbor:"10,keyasint"`                      // Freshness/replay protection
	UEID         []byte `json:"ueid" cbor:"256,keyasint"`                          // Universal Entity ID
	OEMID        int    `json:"oemid,omitempty" cbor:"258,keyasint,omitempty"`     // Hardware OEM ID
	HWModel      []byte `json:"hwmodel,omitempty" cbor:"259,keyasint,omitempty"`   // Hardware model
	HWVersion    string `json:"hwversion,omitempty" cbor:"260,keyasint,omitempty"` // Hardware version
	SWName       string `json:"swname,omitempty" cbor:"270,keyasint,omitempty"`    // Software name
	SWVersion    string `json:"swversion,omitempty" cbor:"271,keyasint,omitempty"` // Software version
	DebugStatus  int    `json:"dbgstat" cbor:"263,keyasint"`                       // Debug status
	Measurements []byte `json:"measurements" cbor:"265,keyasint"`                  // Software measurements

	// Platform type indicator
	PlatformType string `json:"platform_type"`

	// Submodules for vTPM and other components
	Submods map[string]interface{} `json:"submods,omitempty" cbor:"266,keyasint,omitempty"`

	// Platform-specific extensions (custom claims)
	SNPExtensions  *SNPExtensions  `json:"x-cocos-sevsnp,omitempty"`
	TDXExtensions  *TDXExtensions  `json:"x-cocos-tdx,omitempty"`
	VTPMExtensions *VTPMExtensions `json:"x-cocos-vtpm,omitempty"`

	// Original binary report (for verification)
	RawReport []byte `json:"raw_report,omitempty"`
}

// SNPExtensions contains AMD SEV-SNP specific claims.
type SNPExtensions struct {
	Measurement   []byte `json:"measurement"`              // SNP MEASUREMENT field
	TCB           string `json:"tcb"`                      // TCB version info
	PlatformInfo  uint64 `json:"platform_info"`            // PLATFORM_INFO
	Policy        uint64 `json:"policy"`                   // POLICY field
	FamilyID      []byte `json:"family_id,omitempty"`      // Family ID
	ImageID       []byte `json:"image_id,omitempty"`       // Image ID
	VMPL          int    `json:"vmpl,omitempty"`           // VM Privilege Level
	SignatureAlgo int    `json:"signature_algo,omitempty"` // Signature algorithm
	CurrentTCB    uint64 `json:"current_tcb,omitempty"`    // Current TCB
	ReportedTCB   uint64 `json:"reported_tcb,omitempty"`   // Reported TCB
	ChipID        []byte `json:"chip_id,omitempty"`        // Chip ID
	CommittedTCB  uint64 `json:"committed_tcb,omitempty"`  // Committed TCB
	LaunchTCB     uint64 `json:"launch_tcb,omitempty"`     // Launch TCB
}

// TDXExtensions contains Intel TDX specific claims.
type TDXExtensions struct {
	MRTD          []byte         `json:"mrtd"`                      // MRTD measurement
	RTMR          [][]byte       `json:"rtmr"`                      // Runtime measurement registers
	XFAM          uint64         `json:"xfam"`                      // Extended features available mask
	TDAttributes  uint64         `json:"td_attributes"`             // TD attributes
	MRConfigID    []byte         `json:"mr_config_id,omitempty"`    // MR Config ID
	MROwner       []byte         `json:"mr_owner,omitempty"`        // MR Owner
	MROwnerConfig []byte         `json:"mr_owner_config,omitempty"` // MR Owner Config
	MRSEAM        []byte         `json:"mr_seam,omitempty"`         // MR SEAM
	TDXModule     *TDXModuleInfo `json:"tdx_module,omitempty"`      // TDX module info
}

// TDXModuleInfo contains TDX module version information.
type TDXModuleInfo struct {
	Major     uint8  `json:"major"`
	Minor     uint8  `json:"minor"`
	BuildNum  uint16 `json:"build_num"`
	BuildDate uint32 `json:"build_date"`
}

// VTPMExtensions contains vTPM specific claims.
type VTPMExtensions struct {
	PCRs     map[string]string `json:"pcrs"`                // PCR values (SHA256/SHA384)
	EventLog []byte            `json:"event_log,omitempty"` // Event log
	Quote    []byte            `json:"quote,omitempty"`     // TPM quote
}

// DebugStatus constants (RFC 9711 Section 4.2.6).
const (
	DebugEnabled              = 0 // Debug is enabled
	DebugDisabled             = 1 // Debug is disabled
	DebugDisabledSinceBoot    = 2 // Debug is disabled since boot
	DebugPermanentDisable     = 3 // Debug is permanently disabled
	DebugFullPermanentDisable = 4 // Debug is fully and permanently disabled
)

// MinNonceLength defines the minimum length for EAT nonce in bytes.
const MinNonceLength = 8

// NewEATClaims creates EAT claims from binary attestation report.
func NewEATClaims(report []byte, nonce []byte, platformType attestation.PlatformType) (*EATClaims, error) {
	if len(nonce) < MinNonceLength {
		return nil, errors.New("eat_nonce must be at least 8 bytes long")
	}
	claims := &EATClaims{
		Nonce:        nonce,
		PlatformType: getPlatformTypeName(platformType),
		RawReport:    report,
		DebugStatus:  DebugDisabledSinceBoot, // Default to disabled since boot
	}

	// Extract platform-specific claims
	if err := extractPlatformClaims(claims, report, platformType); err != nil {
		return nil, err
	}

	return claims, nil
}

// extractPlatformClaims extracts platform-specific claims from binary report.
func extractPlatformClaims(claims *EATClaims, report []byte, platformType attestation.PlatformType) error {
	switch platformType {
	case attestation.SNP, attestation.SNPvTPM:
		return extractSNPClaims(claims, report)
	case attestation.TDX:
		return extractTDXClaims(claims, report)
	case attestation.VTPM:
		return extractVTPMClaims(claims, report)
	case attestation.Azure:
		return extractAzureClaims(claims, report)
	default:
		// For unknown platforms, just store the raw report
		return nil
	}
}

// getPlatformTypeName converts platform type to string name.
func getPlatformTypeName(platformType attestation.PlatformType) string {
	switch platformType {
	case attestation.SNP:
		return "SNP"
	case attestation.TDX:
		return "TDX"
	case attestation.VTPM:
		return "vTPM"
	case attestation.SNPvTPM:
		return "SNP-vTPM"
	case attestation.Azure:
		return "Azure"
	case attestation.NoCC:
		return "NoCC"
	default:
		return "Unknown"
	}
}

// Sanitize enforces dependency rules for claims.
// HWModel requires OEMID.
// HWVersion requires HWModel.
func (c *EATClaims) Sanitize() {
	if c.OEMID == 0 {
		c.HWModel = nil
		c.HWVersion = ""
	}
	if len(c.HWModel) == 0 {
		c.HWVersion = ""
	}
	if c.SWName == "" {
		c.SWVersion = ""
	}
}
