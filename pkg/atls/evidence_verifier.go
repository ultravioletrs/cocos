// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package atls

import (
	"fmt"
	"os"

	eaattestation "github.com/ultravioletrs/cocos/pkg/atls/eaattestation"
	cocosattestation "github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/azure"
	"github.com/ultravioletrs/cocos/pkg/attestation/eat"
	"github.com/ultravioletrs/cocos/pkg/attestation/tdx"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"github.com/veraison/corim/corim"
)

type policyEvidenceVerifier struct {
	policyPath string
}

func NewEvidenceVerifier(policyPath string) eaattestation.EvidenceVerifier {
	return &policyEvidenceVerifier{policyPath: policyPath}
}

func (v *policyEvidenceVerifier) VerifyEvidence(evidence []byte) error {
	if v.policyPath == "" {
		return fmt.Errorf("atls: attestation policy path is not set")
	}
	claims, err := eat.DecodeCBOR(evidence, nil)
	if err != nil {
		return fmt.Errorf("atls: failed to decode EAT evidence: %w", err)
	}
	manifest, err := loadCoRIM(v.policyPath)
	if err != nil {
		return err
	}
	verifier, err := platformVerifier(platformTypeFromClaims(claims.PlatformType))
	if err != nil {
		return err
	}
	return verifier.VerifyWithCoRIM(claims.RawReport, manifest)
}

func loadCoRIM(path string) (*corim.UnsignedCorim, error) {
	corimBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("atls: failed to read CoRIM file: %w", err)
	}

	var sc corim.SignedCorim
	if err := sc.FromCOSE(corimBytes); err == nil {
		return &sc.UnsignedCorim, nil
	}

	var uc corim.UnsignedCorim
	if err := uc.FromCBOR(corimBytes); err != nil {
		return nil, fmt.Errorf("atls: failed to parse CoRIM: %w", err)
	}
	return &uc, nil
}

func platformTypeFromClaims(name string) cocosattestation.PlatformType {
	switch name {
	case "SNP":
		return cocosattestation.SNP
	case "TDX":
		return cocosattestation.TDX
	case "vTPM":
		return cocosattestation.VTPM
	case "SNP-vTPM":
		return cocosattestation.SNPvTPM
	case "Azure":
		return cocosattestation.Azure
	default:
		return cocosattestation.NoCC
	}
}

func platformVerifier(platformType cocosattestation.PlatformType) (cocosattestation.Verifier, error) {
	switch platformType {
	case cocosattestation.SNP, cocosattestation.SNPvTPM, cocosattestation.VTPM:
		return vtpm.NewVerifier(nil), nil
	case cocosattestation.Azure:
		return azure.NewVerifier(nil), nil
	case cocosattestation.TDX:
		return tdx.NewVerifier(), nil
	default:
		return nil, fmt.Errorf("atls: unsupported platform type: %d", platformType)
	}
}
