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
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	measurementOffset = 0x90
	signatureOffset   = 0x2A0
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

	AttConfigurationSEVSNP = check.Config{
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
			err := fillInAttestationLocal(tt.attestation)
			assert.True(t, errors.Contains(err, tt.err), fmt.Sprintf("expected error %v, got %v", tt.err, err))
		})
	}
}

func TestVerifyAttestationReportSuccess(t *testing.T) {
	file, reportData := prepareForTestVerifyAttestationReport(t)

	tests := []struct {
		name              string
		attestationReport []byte
		reportData        []byte
		goodProduct       int
		err               error
	}{
		{
			name:              "Valid attestation, validation and verification is performed succsessfully",
			attestationReport: file,
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
	file, reportData := prepareForTestVerifyAttestationReport(t)

	// Change random data so in the signature so the signature failes
	file[signatureOffset] = file[signatureOffset] ^ 0x01

	tests := []struct {
		name              string
		attestationReport []byte
		reportData        []byte
		err               error
	}{
		{
			name:              "Valid attestation, distorted signature",
			attestationReport: file,
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
	file, reportData := prepareForTestVerifyAttestationReport(t)

	tests := []struct {
		name              string
		attestationReport []byte
		reportData        []byte
		err               error
	}{
		{
			name:              "Valid attestation, unknown product",
			attestationReport: file,
			reportData:        reportData,
			err:               errProductLine,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			AttConfigurationSEVSNP.RootOfTrust.ProductLine = ""
			AttConfigurationSEVSNP.Policy.Product = nil
			err := VerifyAttestationReportTLS(tt.attestationReport, tt.reportData)
			assert.True(t, errors.Contains(err, tt.err), fmt.Sprintf("expected error %v, got %v", tt.err, err))
		})
	}
}

func TestVerifyAttestationReportMalformedPolicy(t *testing.T) {
	file, reportData := prepareForTestVerifyAttestationReport(t)

	// Change random data in the measurement so the measurement does not match
	file[measurementOffset] = file[measurementOffset] ^ 0x01

	tests := []struct {
		name              string
		attestationReport []byte
		reportData        []byte
		err               error
	}{
		{
			name:              "Valid attestation, malformed policy (measurement)",
			attestationReport: file,
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

func prepareForTestVerifyAttestationReport(t *testing.T) ([]byte, []byte) {
	file, err := os.ReadFile("../../../attestation.bin")
	require.NoError(t, err)

	rr, err := abi.ReportCertsToProto(file)
	require.NoError(t, err)

	if len(file) < attestationReportSize {
		file = append(file, make([]byte, attestationReportSize-len(file))...)
	}

	AttConfigurationSEVSNP = check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}}

	backendinfoFile, err := os.ReadFile("../../../scripts/backend_info/backend_info.json")
	require.NoError(t, err)

	err = protojson.Unmarshal(backendinfoFile, &AttConfigurationSEVSNP)
	require.NoError(t, err)

	AttConfigurationSEVSNP.Policy.Product = &sevsnp.SevProduct{Name: sevsnp.SevProduct_SEV_PRODUCT_MILAN}
	AttConfigurationSEVSNP.Policy.FamilyId = rr.Report.FamilyId
	AttConfigurationSEVSNP.Policy.ImageId = rr.Report.ImageId
	AttConfigurationSEVSNP.Policy.Measurement = rr.Report.Measurement
	AttConfigurationSEVSNP.Policy.HostData = rr.Report.HostData
	AttConfigurationSEVSNP.Policy.ReportIdMa = rr.Report.ReportIdMa
	AttConfigurationSEVSNP.RootOfTrust.ProductLine = sevProductNameMilan

	return file, rr.Report.ReportData
}
