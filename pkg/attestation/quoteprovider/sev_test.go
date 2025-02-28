// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build !embed
// +build !embed

package quoteprovider

import (
	"fmt"
	"os"
	"testing"

	"github.com/absmach/magistrala/pkg/errors"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	config "github.com/ultravioletrs/cocos/pkg/attestation"
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
	attestationPB, reportData := prepareForTestVerifyAttestationReport(t)

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
	attestationPB, reportData := prepareForTestVerifyAttestationReport(t)

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
	attestationPB, reportData := prepareForTestVerifyAttestationReport(t)

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
			config.AttestationPolicy.SnpCheck.RootOfTrust.ProductLine = ""
			config.AttestationPolicy.SnpCheck.Policy.Product = nil
			err := VerifyAttestationReportTLS(tt.attestationReport, tt.reportData)
			assert.True(t, errors.Contains(err, tt.err), fmt.Sprintf("expected error %v, got %v", tt.err, err))
		})
	}
}

func TestVerifyAttestationReportMalformedPolicy(t *testing.T) {
	attestationPB, reportData := prepareForTestVerifyAttestationReport(t)

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

func prepareForTestVerifyAttestationReport(t *testing.T) (*sevsnp.Attestation, []byte) {
	file, err := os.ReadFile("../../../attestation.bin")
	require.NoError(t, err)

	if len(file) < attestationReportSize {
		file = append(file, make([]byte, attestationReportSize-len(file))...)
	}

	rr, err := abi.ReportCertsToProto(file)
	require.NoError(t, err)

	config.AttestationPolicy = config.Config{SnpCheck: &check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}}, PcrConfig: &config.PcrConfig{}}

	attestationPolicyFile, err := os.ReadFile("../../../scripts/attestation_policy/attestation_policy.json")
	require.NoError(t, err)

	unmarshalOptions := protojson.UnmarshalOptions{DiscardUnknown: true}

	err = unmarshalOptions.Unmarshal(attestationPolicyFile, config.AttestationPolicy.SnpCheck)
	require.NoError(t, err)

	config.AttestationPolicy.SnpCheck.Policy.Product = &sevsnp.SevProduct{Name: sevsnp.SevProduct_SEV_PRODUCT_MILAN}
	config.AttestationPolicy.SnpCheck.Policy.FamilyId = rr.Report.FamilyId
	config.AttestationPolicy.SnpCheck.Policy.ImageId = rr.Report.ImageId
	config.AttestationPolicy.SnpCheck.Policy.Measurement = rr.Report.Measurement
	config.AttestationPolicy.SnpCheck.Policy.HostData = rr.Report.HostData
	config.AttestationPolicy.SnpCheck.Policy.ReportIdMa = rr.Report.ReportIdMa
	config.AttestationPolicy.SnpCheck.RootOfTrust.ProductLine = sevProductNameMilan

	return rr, rr.Report.ReportData
}
