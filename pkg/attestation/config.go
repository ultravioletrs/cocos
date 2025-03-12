// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"os"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/google/go-sev-guest/proto/check"
	"google.golang.org/protobuf/encoding/protojson"
)

type AttestationType int32

const (
	SNP AttestationType = iota
	VTPM
	SNPvTPM
)

var (
	AttestationPolicy           = Config{Config: &check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}}, PcrConfig: &PcrConfig{}}
	ErrAttestationPolicyOpen    = errors.New("failed to open Attestation Policy file")
	ErrAttestationPolicyDecode  = errors.New("failed to decode Attestation Policy file")
	ErrAttestationPolicyMissing = errors.New("failed due to missing Attestation Policy file")
	ErrAttestationPolicyEncode  = errors.New("failed to encode the Attestation Policy")
)

type PcrValues struct {
	Sha256 map[string]string `json:"sha256"`
	Sha384 map[string]string `json:"sha384"`
}

type PcrConfig struct {
	PCRValues PcrValues `json:"pcr_values"`
}

type Config struct {
	*check.Config
	*PcrConfig
}

func ReadAttestationPolicy(policyPath string, attestationConfiguration *Config) error {
	if policyPath != "" {
		policyData, err := os.ReadFile(policyPath)
		if err != nil {
			return errors.Wrap(ErrAttestationPolicyOpen, err)
		}

		return ReadAttestationPolicyFromByte(policyData, attestationConfiguration)
	}

	return ErrAttestationPolicyMissing
}

func ReadAttestationPolicyFromByte(policyData []byte, attestationConfiguration *Config) error {
	unmarshalOptions := protojson.UnmarshalOptions{AllowPartial: true, DiscardUnknown: true}

	if err := unmarshalOptions.Unmarshal(policyData, attestationConfiguration.Config); err != nil {
		return errors.Wrap(ErrAttestationPolicyDecode, err)
	}

	if err := json.Unmarshal(policyData, attestationConfiguration.PcrConfig); err != nil {
		return errors.Wrap(ErrAttestationPolicyDecode, err)
	}

	return nil
}
