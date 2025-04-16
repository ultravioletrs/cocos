// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

type ConfidentialComputing int

const (
	SEVSNP ConfidentialComputing = iota
	Azure
	NoCC
)

const (
	devSnp           = "/dev/sev-guest"
	azureMetadataUrl = "http://169.254.169.254/metadata/instance"
	azureApiVersion  = "2021-02-01"
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
	Sha1   map[string]string `json:"sha1"`
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

// CCPlatform returns the type of the confidential computing platform.
func CCPlatform() ConfidentialComputing {
	if checkSEVSNP() {
		return SEVSNP
	}

	if isAzureVM() {
		return Azure
	}

	return NoCC
}

func checkSEVSNP() bool {
	if _, err := os.Stat(devSnp); err == nil {
		return true
	}

	return false
}

func isAzureVM() bool {
	client := &http.Client{}
	url := fmt.Sprintf("%s?api-version=%s", azureMetadataUrl, azureApiVersion)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Metadata", "true")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return len(body) > 0
	}

	return false
}
