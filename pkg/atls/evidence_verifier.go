// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package atls

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	eaattestation "github.com/ultravioletrs/cocos/pkg/atls/eaattestation"
	cocosattestation "github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/azure"
	"github.com/ultravioletrs/cocos/pkg/attestation/eat"
	"github.com/ultravioletrs/cocos/pkg/attestation/gpu"
	"github.com/ultravioletrs/cocos/pkg/attestation/tdx"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"github.com/veraison/corim/corim"
)

type policyEvidenceVerifier struct {
	policyPath     string
	loadManifest   func(string) (*corim.UnsignedCorim, error)
	rootVerifier   func(cocosattestation.PlatformType) (cocosattestation.Verifier, error)
	newGPUVerifier func() (cocosattestation.Verifier, error)
}

func NewEvidenceVerifier(policyPath string) eaattestation.EvidenceVerifier {
	return &policyEvidenceVerifier{
		policyPath:     policyPath,
		loadManifest:   loadCoRIM,
		rootVerifier:   platformVerifier,
		newGPUVerifier: defaultGPUVerifier,
	}
}

func (v *policyEvidenceVerifier) VerifyEvidence(evidence []byte) error {
	if v.policyPath == "" {
		return fmt.Errorf("atls: attestation policy path is not set")
	}
	claims, err := eat.DecodeCBOR(evidence, nil)
	if err != nil {
		return fmt.Errorf("atls: failed to decode EAT evidence: %w", err)
	}
	manifest, err := v.loadManifest(v.policyPath)
	if err != nil {
		return err
	}
	verifier, err := v.rootVerifier(platformTypeFromClaims(claims.PlatformType))
	if err != nil {
		return err
	}
	if err := verifier.VerifyWithCoRIM(claims.RawReport, manifest); err != nil {
		return err
	}

	if claims.GPUExtensions != nil {
		if err := v.verifyGPUEvidence(claims, manifest); err != nil {
			return err
		}
	}

	return nil
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

func defaultGPUVerifier() (cocosattestation.Verifier, error) {
	timeout := 30 * time.Second
	if rawTimeout := os.Getenv("ATLS_GPU_VERIFIER_TIMEOUT"); rawTimeout != "" {
		parsed, err := time.ParseDuration(rawTimeout)
		if err != nil {
			return nil, fmt.Errorf("atls: invalid ATLS_GPU_VERIFIER_TIMEOUT: %w", err)
		}
		timeout = parsed
	}

	binaryPath := os.Getenv("ATLS_GPU_VERIFIER_PATH")
	if binaryPath == "" {
		binaryPath = os.Getenv("ATTESTATION_GPU_HELPER_PATH")
	}

	return gpu.NewVerifier(binaryPath, timeout)
}

func (v *policyEvidenceVerifier) verifyGPUEvidence(claims *eat.EATClaims, manifest *corim.UnsignedCorim) error {
	if len(claims.GPUExtensions.EvidenceJSON) == 0 {
		return fmt.Errorf("atls: gpu evidence is empty")
	}

	expectedNonce := sha256.Sum256(append(append([]byte(nil), claims.Nonce...), []byte(":gpu")...))
	if !bytes.Equal(claims.GPUExtensions.Nonce, expectedNonce[:]) {
		return fmt.Errorf("atls: gpu nonce binding mismatch")
	}

	// Guard against replay: a stale self-consistent EvidenceJSON blob can be
	// paired with a rewritten outer Nonce unless the inner nonce is also checked.
	var envelopes []struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(claims.GPUExtensions.EvidenceJSON, &envelopes); err != nil {
		return fmt.Errorf("atls: failed to parse GPU evidence JSON: %w", err)
	}
	if len(envelopes) == 0 || strings.TrimSpace(envelopes[0].Nonce) == "" {
		return fmt.Errorf("atls: GPU evidence JSON missing nonce")
	}
	if envelopes[0].Nonce != hex.EncodeToString(expectedNonce[:]) {
		return fmt.Errorf("atls: gpu evidence nonce mismatch")
	}

	verifier, err := v.newGPUVerifier()
	if err != nil {
		return err
	}

	return verifier.VerifyWithCoRIM(claims.GPUExtensions.EvidenceJSON, manifest)
}
