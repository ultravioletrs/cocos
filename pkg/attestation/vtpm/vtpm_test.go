// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package vtpm

import (
	"fmt"
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
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"google.golang.org/protobuf/encoding/protojson"
)

const sevSnpProductMilan = "Milan"

var policy = attestation.Config{Config: &check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}}, PcrConfig: &attestation.PcrConfig{}}

func TestVerifyAttestationReportMalformedSignature(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "policy")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	attestationPB, reportData := prepVerifyAttReport(t)
	err = setAttestationPolicy(attestationPB, tempDir)
	require.NoError(t, err)

	// Change random data so in the signature so the signature failes
	attestationPB.Report.Signature[0] = attestationPB.Report.Signature[0] ^ 0x01

	tests := []struct {
		name              string
		attestationReport *sevsnp.Attestation
		reportData        []byte
		err               error
	}{
		{
			name:              "Valid attestation, distorted signature",
			attestationReport: attestationPB,
			reportData:        reportData,
			err:               quoteprovider.ErrAttVerification,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := quoteprovider.VerifyAttestationReportTLS(tt.attestationReport, tt.reportData, &policy)
			assert.True(t, errors.Contains(err, tt.err), fmt.Sprintf("expected error %v, got %v", tt.err, err))
		})
	}
}

func TestVerifyAttestationReportUnknownProduct(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "policy")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	attestationPB, reportData := prepVerifyAttReport(t)
	err = setAttestationPolicy(attestationPB, tempDir)
	require.NoError(t, err)

	err = changeProductAttestationPolicy()
	require.NoError(t, err)

	tests := []struct {
		name              string
		attestationReport *sevsnp.Attestation
		reportData        []byte
		err               error
	}{
		{
			name:              "Valid attestation, unknown product",
			attestationReport: attestationPB,
			reportData:        reportData,
			err:               quoteprovider.ErrProductLine,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := quoteprovider.VerifyAttestationReportTLS(tt.attestationReport, tt.reportData, &policy)
			assert.True(t, errors.Contains(err, tt.err), fmt.Sprintf("expected error %v, got %v", tt.err, err))
		})
	}
}

func TestVerifyAttestationReportSuccess(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "policy")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	attestationPB, reportData := prepVerifyAttReport(t)
	err = setAttestationPolicy(attestationPB, tempDir)
	require.NoError(t, err)

	tests := []struct {
		name              string
		attestationReport *sevsnp.Attestation
		reportData        []byte
		goodProduct       int
		err               error
	}{
		{
			name:              "Valid attestation, validation and verification is performed succsessfully",
			attestationReport: attestationPB,
			reportData:        reportData,
			goodProduct:       1,
			err:               nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := quoteprovider.VerifyAttestationReportTLS(tt.attestationReport, tt.reportData, &policy)
			assert.True(t, errors.Contains(err, tt.err), fmt.Sprintf("expected error %v, got %v", tt.err, err))
		})
	}
}

func TestVerifyAttestationReportMalformedPolicy(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "policy")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	attestationPB, reportData := prepVerifyAttReport(t)
	err = setAttestationPolicy(attestationPB, tempDir)
	require.NoError(t, err)

	// Change random data in the measurement so the measurement does not match
	attestationPB.Report.Measurement[0] = attestationPB.Report.Measurement[0] ^ 0x01

	tests := []struct {
		name              string
		attestationReport *sevsnp.Attestation
		reportData        []byte
		err               error
	}{
		{
			name:              "Valid attestation, malformed policy (measurement)",
			attestationReport: attestationPB,
			reportData:        reportData,
			err:               quoteprovider.ErrAttVerification,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := quoteprovider.VerifyAttestationReportTLS(tt.attestationReport, tt.reportData, &policy)
			assert.True(t, errors.Contains(err, tt.err), fmt.Sprintf("expected error %v, got %v", tt.err, err))
		})
	}
}

func prepVerifyAttReport(t *testing.T) (*sevsnp.Attestation, []byte) {
	file, err := os.ReadFile("../../../attestation.bin")
	require.NoError(t, err)

	if len(file) < abi.ReportSize {
		file = append(file, make([]byte, abi.ReportSize-len(file))...)
	}

	rr, err := abi.ReportCertsToProto(file)
	require.NoError(t, err)

	return rr, rr.Report.ReportData
}

func setAttestationPolicy(rr *sevsnp.Attestation, policyDirectory string) error {
	attestationPolicyFile, err := os.ReadFile("../../../scripts/attestation_policy/attestation_policy.json")
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
	policy.Config.RootOfTrust.ProductLine = sevSnpProductMilan

	policyByte, err := ConvertPolicyToJSON(&policy)
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

func changeProductAttestationPolicy() error {
	err := ReadPolicy(attestation.AttestationPolicyPath, &policy)
	if err != nil {
		return err
	}

	policy.Config.RootOfTrust.ProductLine = ""
	policy.Config.Policy.Product = nil

	policyByte, err := ConvertPolicyToJSON(&policy)
	if err != nil {
		return err
	}

	if err := os.WriteFile(attestation.AttestationPolicyPath, policyByte, 0o644); err != nil {
		return nil
	}

	return nil
}
