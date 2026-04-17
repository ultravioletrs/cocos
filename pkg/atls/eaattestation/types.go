// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"encoding/json"
	"errors"
)

var (
	ErrMalformedPayload            = errors.New("attestation: malformed payload")
	ErrMissingStatement            = errors.New("attestation: missing evidence or attestation results")
	ErrMissingBinder               = errors.New("attestation: missing attestation binder")
	ErrAIKPubHashMismatch          = errors.New("attestation: AIK public key hash mismatch")
	ErrBindingMismatch             = errors.New("attestation: attestation binding mismatch")
	ErrUnexpectedExporterLabel     = errors.New("attestation: unexpected exporter label")
	ErrMissingAttestation          = errors.New("attestation: missing attestation payload")
	ErrEvidenceVerificationMissing = errors.New("attestation: evidence verifier not configured")
	ErrResultsVerificationMissing  = errors.New("attestation: attestation results verifier not configured")
)

// Payload models the attestation document carried inside the EA certificate-entry extension.
// It intentionally separates the attestation statement from the TLS binding material.
type Payload struct {
	Version            int               `json:"version"`
	MediaType          string            `json:"media_type,omitempty"`
	Evidence           []byte            `json:"evidence,omitempty"`
	AttestationResults []byte            `json:"attestation_results,omitempty"`
	Binder             AttestationBinder `json:"binder"`
}

type AttestationBinder struct {
	ExporterLabel string `json:"exporter_label,omitempty"`
	AIKPubHash    []byte `json:"aik_pub_hash,omitempty"`
	Binding       []byte `json:"binding,omitempty"`
}

type VerifiedPayload struct {
	Payload           *Payload
	EvidenceVerified  bool
	ResultsVerified   bool
	BindingVerified   bool
	UsedExporterLabel string
}

func (p *Payload) Validate() error {
	if p == nil {
		return ErrMalformedPayload
	}
	if len(p.Evidence) == 0 && len(p.AttestationResults) == 0 {
		return ErrMissingStatement
	}
	if len(p.Binder.AIKPubHash) == 0 || len(p.Binder.Binding) == 0 {
		return ErrMissingBinder
	}
	return nil
}

func (p *Payload) NormalizedExporterLabel(defaultLabel string) string {
	if p == nil || p.Binder.ExporterLabel == "" {
		return defaultLabel
	}
	return p.Binder.ExporterLabel
}

func (p *Payload) VerifyExporterLabel(expectedLabel string) error {
	if p == nil {
		return ErrMalformedPayload
	}
	if p.Binder.ExporterLabel != "" && p.Binder.ExporterLabel != expectedLabel {
		return ErrUnexpectedExporterLabel
	}
	return nil
}

func MarshalPayload(p Payload) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.Version == 0 {
		p.Version = 1
	}
	return json.Marshal(p)
}

func ParsePayload(raw []byte) (*Payload, error) {
	if len(raw) == 0 {
		return nil, ErrMalformedPayload
	}
	var p Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, ErrMalformedPayload
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}
