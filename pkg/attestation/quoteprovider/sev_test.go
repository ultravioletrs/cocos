// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build !embed
// +build !embed

package quoteprovider

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
	"google.golang.org/protobuf/encoding/protojson"
)

func TestFillInAttestationLocal(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "test_home")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	cocosDir := tempDir + "/.cocos/Milan"
	err = os.MkdirAll(cocosDir, 0o755)
	require.NoError(t, err)

	bundleContent := []byte("mock ASK ARK bundle")
	err = os.WriteFile(cocosDir+"/ask_ark.pem", bundleContent, 0o644)
	require.NoError(t, err)

	config := check.Config{
		RootOfTrust: &check.RootOfTrust{},
		Policy:      &check.Policy{},
	}

	tests := []struct {
		name        string
		attestation *sevsnp.Attestation
		err         error
	}{
		{
			name: "Empty attestation",
			attestation: &sevsnp.Attestation{
				CertificateChain: &sevsnp.CertificateChain{},
			},
			err: nil,
		},
		{
			name: "Attestation with existing chain",
			attestation: &sevsnp.Attestation{
				CertificateChain: &sevsnp.CertificateChain{
					AskCert: []byte("existing ASK cert"),
					ArkCert: []byte("existing ARK cert"),
				},
			},
			err: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := fillInAttestationLocal(tt.attestation, &config)
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
			err := VerifyAttestationReportTLS(tt.attestationReport, tt.reportData)
			assert.True(t, errors.Contains(err, tt.err), fmt.Sprintf("expected error %v, got %v", tt.err, err))
		})
	}
}

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
			err:               errAttVerification,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyAttestationReportTLS(tt.attestationReport, tt.reportData)
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
			err:               errProductLine,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyAttestationReportTLS(tt.attestationReport, tt.reportData)
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
			err:               errAttVerification,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyAttestationReportTLS(tt.attestationReport, tt.reportData)
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
	policy := attestation.Config{Config: &check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}}, PcrConfig: &attestation.PcrConfig{}}

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
	policy.Config.RootOfTrust.ProductLine = sevProductNameMilan

	policyByte, err := ConvertSEVSNPAttestationPolicyToJSON(&policy)
	if err != nil {
		return err
	}

	policyPath := filepath.Join(policyDirectory, "attestation_policy.json")
	if err := os.WriteFile(policyPath, policyByte, 0644); err != nil {
		return nil
	}

	attestation.AttestationPolicyPath = policyPath

	return nil
}

func changeProductAttestationPolicy() error {
	policy := attestation.Config{Config: &check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}}, PcrConfig: &attestation.PcrConfig{}}
	err := ReadSEVSNPAttestationPolicy(attestation.AttestationPolicyPath, &policy)
	if err != nil {
		return err
	}

	policy.Config.RootOfTrust.ProductLine = ""
	policy.Config.Policy.Product = nil

	policyByte, err := ConvertSEVSNPAttestationPolicyToJSON(&policy)
	if err != nil {
		return err
	}

	if err := os.WriteFile(attestation.AttestationPolicyPath, policyByte, 0644); err != nil {
		return nil
	}

	return nil
}
