// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"fmt"
	"io"
	"net/http"

	"github.com/google/go-sev-guest/client"
	"github.com/google/go-sev-guest/proto/check"
	tdxcliet "github.com/google/go-tdx-guest/client"
	"github.com/google/go-tpm/legacy/tpm2"
)

type PlatformType int

const (
	SNP PlatformType = iota
	VTPM
	SNPvTPM
	Azure
	TDX
	NoCC
)

const (
	azureMetadataUrl = "http://169.254.169.254/metadata/instance"
	azureApiVersion  = "2021-02-01"
)

var AttestationPolicyPath string

type PcrValues struct {
	Sha256 map[string]string `json:"sha256"`
	Sha384 map[string]string `json:"sha384"`
	Sha1   map[string]string `json:"sha1"`
}

type PcrConfig struct {
	PCRValues PcrValues `json:"pcr_values"`
}

// Config represents attestation configuration.
type Config struct {
	*check.Config
	*PcrConfig
	*EATValidation
}

// EATValidation contains EAT token validation settings
type EATValidation struct {
	RequireEATFormat   bool     `json:"require_eat_format"`
	AllowedFormats     []string `json:"allowed_formats"`
	MaxTokenAgeSeconds int      `json:"max_token_age_seconds"`
	RequireClaims      []string `json:"require_claims"`
	VerifySignature    bool     `json:"verify_signature"`
}

type ccCheck struct {
	checkFunc func() bool
	platform  PlatformType
}

type Provider interface {
	Attestation(teeNonce []byte, vTpmNonce []byte) ([]byte, error)
	TeeAttestation(teeNonce []byte) ([]byte, error)
	VTpmAttestation(vTpmNonce []byte) ([]byte, error)
	AzureAttestationToken(tokenNonce []byte) ([]byte, error)
}

type Verifier interface {
	VerifyAttestation(report []byte, teeNonce []byte, vTpmNonce []byte) error
	VerifyEAT(eatToken []byte, teeNonce []byte, vTpmNonce []byte) error
	VerifTeeAttestation(report []byte, teeNonce []byte) error
	VerifVTpmAttestation(report []byte, vTpmNonce []byte) error
	JSONToPolicy(path string) error
}

// CCPlatform returns the type of the confidential computing platform.
func CCPlatform() PlatformType {
	checks := []ccCheck{
		{SevSnpGuestvTPMExists, SNPvTPM},
		{SevSnpGuestDeviceExists, SNP},
		{isAzureVM, Azure},
		{TDXGuestDeviceExists, TDX},
	}

	for _, c := range checks {
		if c.checkFunc() {
			return c.platform
		}
	}
	return NoCC
}

func SevSnpGuestDeviceExists() bool {
	d, err := client.OpenDevice()
	if err != nil {
		return false
	}
	d.Close()

	return true
}

func SevSnpGuestvTPMExists() bool {
	return vTPMExists() && SevSnpGuestDeviceExists()
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

func TDXGuestDeviceExists() bool {
	d, err := tdxcliet.OpenDevice()
	if err != nil {
		return false
	}
	d.Close()

	return true
}
