// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/google/go-sev-guest/client"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-tpm/legacy/tpm2"
	"google.golang.org/protobuf/encoding/protojson"
)

type PlatformType int

const (
	SNP PlatformType = iota
	VTPM
	SNPvTPM
	AzureToken
	Azure
	NoCC
)

const (
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

type ccCheck struct {
	checkFunc func() bool
	platform  PlatformType
}

type Provider interface {
	Attestation(teeNonce []byte, vTpmNonce []byte) ([]byte, error)
	TeeAttestation(teeNonce []byte) ([]byte, error)
	VTpmAttestation(vTpmNonce []byte) ([]byte, error)
	VerifyAttestation(report []byte, teeNonce []byte, vTpmNonce []byte) error
	VerifTeeAttestation(report []byte, teeNonce []byte) error
	VerifVTpmAttestation(report []byte, vTpmNonce []byte) error
	AzureAttestationToken(tokenNonce []byte) ([]byte, error)
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
func CCPlatform() PlatformType {
	checks := []ccCheck{
		{SevGuestvTPMExists, SNPvTPM},
		{SevGuesDeviceExists, SNP},
		{isAzureVM, Azure},
	}

	for _, c := range checks {
		if c.checkFunc() {
			return c.platform
		}
	}
	return NoCC
}

func SevGuesDeviceExists() bool {
	d, err := client.OpenDevice()
	if err != nil {
		return false
	}
	d.Close()

	return true
}

func SevGuestvTPMExists() bool {
	return vTPMExists() && SevGuesDeviceExists()
}

func vTPMExists() bool {
	d, err := tpm2.OpenTPM()
	if err != nil {
		return false
	}
	d.Close()

	return true
}

func isAzureVM() bool {
	if !vTPMExists() {
		return false
	}

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
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return false
		}

		return len(body) > 0
	}

	return false
}
