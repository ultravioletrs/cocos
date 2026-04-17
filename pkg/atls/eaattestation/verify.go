// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
)

type EvidenceVerifier interface {
	VerifyEvidence(evidence []byte) error
}

type ResultsVerifier interface {
	VerifyAttestationResults(results []byte) error
}

type VerificationPolicy struct {
	EvidenceVerifier EvidenceVerifier
	ResultsVerifier  ResultsVerifier
}

func (p VerificationPolicy) RequiresAttestation() bool {
	return p.EvidenceVerifier != nil || p.ResultsVerifier != nil
}

func VerifyPayload(st *tls.ConnectionState, defaultLabel string, certificateRequestContext []byte, leaf *x509.Certificate, payload *Payload, policy VerificationPolicy) (*VerifiedPayload, error) {
	if err := payload.Validate(); err != nil {
		return nil, err
	}
	if err := payload.VerifyExporterLabel(defaultLabel); err != nil {
		return nil, err
	}

	verified := &VerifiedPayload{
		Payload:           payload,
		UsedExporterLabel: defaultLabel,
	}

	if err := VerifyBinder(st, verified.UsedExporterLabel, certificateRequestContext, leaf, payload.Binder); err != nil {
		return nil, err
	}
	verified.BindingVerified = true

	if len(payload.Evidence) > 0 && policy.EvidenceVerifier != nil {
		if err := policy.EvidenceVerifier.VerifyEvidence(payload.Evidence); err != nil {
			return nil, err
		}
		verified.EvidenceVerified = true
	} else if len(payload.Evidence) > 0 {
		return nil, ErrEvidenceVerificationMissing
	}
	if len(payload.AttestationResults) > 0 && policy.ResultsVerifier != nil {
		if err := policy.ResultsVerifier.VerifyAttestationResults(payload.AttestationResults); err != nil {
			return nil, err
		}
		verified.ResultsVerified = true
	} else if len(payload.AttestationResults) > 0 {
		return nil, ErrResultsVerificationMissing
	}
	return verified, nil
}

func VerifyBinder(st *tls.ConnectionState, label string, certificateRequestContext []byte, leaf *x509.Certificate, binder AttestationBinder) error {
	exportedValue, aikPubHash, binding, err := ComputeBinding(st, label, certificateRequestContext, leaf)
	if err != nil {
		return err
	}
	_ = exportedValue
	if !equalBytes(aikPubHash, binder.AIKPubHash) {
		return ErrAIKPubHashMismatch
	}
	if !equalBytes(binding, binder.Binding) {
		return ErrBindingMismatch
	}
	return nil
}

func equalBytes(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
