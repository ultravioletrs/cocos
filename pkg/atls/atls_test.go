// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package atls

import (
	"encoding/asn1"
	"os"
	"path/filepath"
	"testing"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
	"google.golang.org/protobuf/encoding/protojson"
)

const sevProductNameMilan = "Milan"

var policy = attestation.Config{Config: &check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}}, PcrConfig: &attestation.PcrConfig{}}

func TestGetPlatformProvider(t *testing.T) {
	cases := []struct {
		name          string
		platformType  attestation.PlatformType
		expectedError error
	}{
		{
			name:          "Valid platform type SNPvTPM",
			platformType:  attestation.SNPvTPM,
			expectedError: nil,
		},
		{
			name:          "Valid platform type Azure",
			platformType:  attestation.Azure,
			expectedError: nil,
		},
		{
			name:          "Valid platform type TDX",
			platformType:  attestation.TDX,
			expectedError: nil,
		},
		{
			name:          "Invalid platform type",
			platformType:  999,
			expectedError: errors.New("unsupported platform type: 999"),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			provider, err := getPlatformProvider(c.platformType)

			if c.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, c.expectedError.Error(), err.Error())
				assert.Nil(t, provider)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, provider)
			}
		})
	}
}

func TestGetPlatformVerifier(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "policy")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	attestationPB := prepVerifyAttReport(t)
	err = setAttestationPolicy(attestationPB, tempDir)
	require.NoError(t, err)

	cases := []struct {
		name          string
		platformType  attestation.PlatformType
		expectedError error
	}{
		{
			name:          "Valid platform type SNPvTPM",
			platformType:  attestation.SNPvTPM,
			expectedError: nil,
		},
		{
			name:          "Valid platform type Azure",
			platformType:  attestation.Azure,
			expectedError: nil,
		},
		{
			name:          "Valid platform type TDX",
			platformType:  attestation.TDX,
			expectedError: errors.New("unknown field \"pcr_values\""),
		},
		{
			name:          "Invalid platform type",
			platformType:  999,
			expectedError: errors.New("unsupported platform type: 999"),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			verifier, err := getPlatformVerifier(c.platformType)

			if c.expectedError != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), c.expectedError.Error())
				assert.Nil(t, verifier)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, verifier)
			}
		})
	}
}

func TestGetOID(t *testing.T) {
	cases := []struct {
		name          string
		platformType  attestation.PlatformType
		expectedOID   asn1.ObjectIdentifier
		expectedError error
	}{
		{
			name:          "Valid platform type SNPvTPM",
			platformType:  attestation.SNPvTPM,
			expectedOID:   SNPvTPMOID,
			expectedError: nil,
		},
		{
			name:          "Valid platform type Azure",
			platformType:  attestation.Azure,
			expectedOID:   AzureOID,
			expectedError: nil,
		},
		{
			name:          "Valid platform type TDX",
			platformType:  attestation.TDX,
			expectedOID:   TDXOID,
			expectedError: nil,
		},
		{
			name:          "Invalid platform type",
			platformType:  999,
			expectedOID:   nil,
			expectedError: errors.New("unsupported platform type: 999"),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			oid, err := getOID(c.platformType)

			if c.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, c.expectedError.Error(), err.Error())
				assert.Nil(t, oid)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, c.expectedOID, oid)
			}
		})
	}
}

func TestGetPlatformTypeFromOID(t *testing.T) {
	cases := []struct {
		name          string
		oid           asn1.ObjectIdentifier
		expectedType  attestation.PlatformType
		expectedError error
	}{
		{
			name:          "Valid OID for SNPvTPM",
			oid:           SNPvTPMOID,
			expectedType:  attestation.SNPvTPM,
			expectedError: nil,
		},
		{
			name:          "Valid OID for Azure",
			oid:           AzureOID,
			expectedType:  attestation.Azure,
			expectedError: nil,
		},
		{
			name:          "Valid OID for TDX",
			oid:           TDXOID,
			expectedType:  attestation.TDX,
			expectedError: nil,
		},
		{
			name:          "Invalid OID",
			oid:           asn1.ObjectIdentifier{1, 2, 3},
			expectedType:  0,
			expectedError: errors.New("unsupported OID: 1.2.3"),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pType, err := GetPlatformTypeFromOID(c.oid)

			if c.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, c.expectedError.Error(), err.Error())
				assert.Equal(t, attestation.PlatformType(0), pType)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, c.expectedType, pType)
			}
		})
	}
}

func prepVerifyAttReport(t *testing.T) *sevsnp.Attestation {
	file, err := os.ReadFile("../../attestation.bin")
	require.NoError(t, err)

	if len(file) < abi.ReportSize {
		file = append(file, make([]byte, abi.ReportSize-len(file))...)
	}

	rr, err := abi.ReportCertsToProto(file)
	require.NoError(t, err)

	return rr
}

func setAttestationPolicy(rr *sevsnp.Attestation, policyDirectory string) error {
	attestationPolicyFile, err := os.ReadFile("../../scripts/attestation_policy/attestation_policy.json")
	if err != nil {
		return err
	}

	unmarshalOptions := protojson.UnmarshalOptions{DiscardUnknown: true}

	err = unmarshalOptions.Unmarshal(attestationPolicyFile, policy)
	if err != nil {
		return err
	}

	policy.Config.Policy.Product = &sevsnp.SevProduct{Name: sevsnp.SevProduct_SEV_PRODUCT_MILAN}
	policy.Config.Policy.FamilyId = rr.Report.FamilyId
	policy.Config.Policy.ImageId = rr.Report.ImageId
	policy.Config.Policy.Measurement = rr.Report.Measurement
	policy.Config.Policy.HostData = rr.Report.HostData
	policy.Config.Policy.ReportIdMa = rr.Report.ReportIdMa
	policy.Config.RootOfTrust.ProductLine = sevProductNameMilan

	policyByte, err := vtpm.ConvertPolicyToJSON(&policy)
	if err != nil {
		return err
	}

	policyPath := filepath.Join(policyDirectory, "attestation_policy.json")

	err = os.WriteFile(policyPath, policyByte, 0o644)
	if err != nil {
		return nil
	}

	attestation.AttestationPolicyPath = policyPath

	return nil
}
