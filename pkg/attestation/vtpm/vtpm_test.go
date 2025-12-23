// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package vtpm

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-tpm-tools/proto/attest"
	ptpm "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"google.golang.org/protobuf/encoding/protojson"
)

const sevSnpProductMilan = "Milan"

var policy = attestation.Config{Config: &check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}}, PcrConfig: &attestation.PcrConfig{}}

type mockTPM struct {
	*bytes.Buffer
	closeErr error
}

func (m *mockTPM) Close() error {
	return m.closeErr
}

type mockWriter struct {
	data []byte
	err  error
}

func (m *mockWriter) Write(p []byte) (n int, err error) {
	if m.err != nil {
		return 0, m.err
	}
	m.data = append(m.data, p...)
	return len(p), nil
}

func TestOpenTpm(t *testing.T) {
	tests := []struct {
		name        string
		externalTPM io.ReadWriteCloser
		expectError bool
	}{
		{
			name:        "External TPM available",
			externalTPM: &mockTPM{Buffer: &bytes.Buffer{}},
			expectError: false,
		},
		{
			name:        "No external TPM",
			externalTPM: nil,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalExternalTPM := ExternalTPM
			defer func() { ExternalTPM = originalExternalTPM }()

			ExternalTPM = tt.externalTPM

			tpm, err := OpenTpm()
			if tt.expectError {
				assert.Error(t, err)
			} else {
				if tt.externalTPM != nil {
					assert.NoError(t, err)
					assert.NotNil(t, tpm)
				}
			}
		})
	}
}

func TestTpmEventLog(t *testing.T) {
	tempFile, err := os.CreateTemp("", "event_log")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	testData := []byte("test event log data")
	_, err = tempFile.Write(testData)
	require.NoError(t, err)
	tempFile.Close()

	tpm := &tpm{ReadWriteCloser: &mockTPM{Buffer: &bytes.Buffer{}}}

	_, err = tpm.EventLog()
	assert.Error(t, err)
}

func TestNewProvider(t *testing.T) {
	tests := []struct {
		name           string
		teeAttestation bool
		vmpl           uint
	}{
		{
			name:           "TEE attestation enabled",
			teeAttestation: true,
			vmpl:           1,
		},
		{
			name:           "TEE attestation disabled",
			teeAttestation: false,
			vmpl:           0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewProvider(tt.teeAttestation, tt.vmpl)
			assert.NotNil(t, provider)
		})
	}
}

func TestProviderAzureAttestationToken(t *testing.T) {
	provider := NewProvider(false, 0)

	token, err := provider.AzureAttestationToken([]byte("test-nonce"))
	assert.Error(t, err)
	assert.Nil(t, token)
	assert.Contains(t, err.Error(), "Azure attestation token is not supported")
}

func TestNewVerifier(t *testing.T) {
	writer := &mockWriter{}
	verifier := NewVerifier(writer)

	assert.NotNil(t, verifier)
}

func TestNewVerifierWithPolicy(t *testing.T) {
	writer := &mockWriter{}
	policy := &attestation.Config{
		Config:    &check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}},
		PcrConfig: &attestation.PcrConfig{},
	}

	tests := []struct {
		name   string
		policy *attestation.Config
	}{
		{
			name:   "With policy",
			policy: policy,
		},
		{
			name:   "Without policy (nil)",
			policy: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verifier := NewVerifierWithPolicy([]byte("test-key"), writer, tt.policy)
			assert.NotNil(t, verifier)
		})
	}
}

func TestMarshalQuote(t *testing.T) {
	tests := []struct {
		name        string
		attestation *attest.Attestation
		expectError bool
	}{
		{
			name: "Valid attestation",
			attestation: &attest.Attestation{
				AkPub: []byte("test-key"),
			},
			expectError: false,
		},
		{
			name:        "Nil attestation",
			attestation: nil,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := marshalQuote(tt.attestation)
			if tt.expectError {
				assert.Error(t, err)
				assert.Empty(t, data)
			} else {
				assert.NoError(t, err)
				if tt.attestation != nil {
					assert.NotEmpty(t, data)
				}
			}
		})
	}
}

func TestCheckExpectedPCRValues(t *testing.T) {
	testPCRValue := make([]byte, 32)
	for i := range testPCRValue {
		testPCRValue[i] = byte(i)
	}

	tests := []struct {
		name        string
		attestation *attest.Attestation
		policy      *attestation.Config
		expectError bool
		errorMsg    string
	}{
		{
			name: "Matching PCR values SHA256",
			attestation: &attest.Attestation{
				Quotes: []*ptpm.Quote{
					{
						Pcrs: &ptpm.PCRs{
							Hash: ptpm.HashAlgo_SHA256,
							Pcrs: map[uint32][]byte{
								0: testPCRValue,
							},
						},
					},
				},
			},
			policy: &attestation.Config{
				PcrConfig: &attestation.PcrConfig{
					PCRValues: attestation.PcrValues{
						Sha256: map[string]string{
							"0": hex.EncodeToString(testPCRValue),
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "Mismatched PCR values",
			attestation: &attest.Attestation{
				Quotes: []*ptpm.Quote{
					{
						Pcrs: &ptpm.PCRs{
							Hash: ptpm.HashAlgo_SHA256,
							Pcrs: map[uint32][]byte{
								0: testPCRValue,
							},
						},
					},
				},
			},
			policy: &attestation.Config{
				PcrConfig: &attestation.PcrConfig{
					PCRValues: attestation.PcrValues{
						Sha256: map[string]string{
							"0": hex.EncodeToString(make([]byte, 32)),
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "expected",
		},
		{
			name: "Unsupported hash algorithm",
			attestation: &attest.Attestation{
				Quotes: []*ptpm.Quote{
					{
						Pcrs: &ptpm.PCRs{
							Hash: ptpm.HashAlgo_HASH_INVALID,
							Pcrs: map[uint32][]byte{
								0: testPCRValue,
							},
						},
					},
				},
			},
			policy: &attestation.Config{
				PcrConfig: &attestation.PcrConfig{},
			},
			expectError: true,
			errorMsg:    "hash algo is not supported",
		},
		{
			name: "Invalid PCR index",
			attestation: &attest.Attestation{
				Quotes: []*ptpm.Quote{
					{
						Pcrs: &ptpm.PCRs{
							Hash: ptpm.HashAlgo_SHA256,
							Pcrs: map[uint32][]byte{
								0: testPCRValue,
							},
						},
					},
				},
			},
			policy: &attestation.Config{
				PcrConfig: &attestation.PcrConfig{
					PCRValues: attestation.PcrValues{
						Sha256: map[string]string{
							"invalid": hex.EncodeToString(testPCRValue),
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "error converting PCR index to int32",
		},
		{
			name: "Invalid PCR value hex",
			attestation: &attest.Attestation{
				Quotes: []*ptpm.Quote{
					{
						Pcrs: &ptpm.PCRs{
							Hash: ptpm.HashAlgo_SHA256,
							Pcrs: map[uint32][]byte{
								0: testPCRValue,
							},
						},
					},
				},
			},
			policy: &attestation.Config{
				PcrConfig: &attestation.PcrConfig{
					PCRValues: attestation.PcrValues{
						Sha256: map[string]string{
							"0": "invalid-hex",
						},
					},
				},
			},
			expectError: true,
			errorMsg:    "error converting PCR value to byte",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkExpectedPCRValues(tt.attestation, tt.policy)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReadPolicy(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "policy_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	validPolicy := map[string]any{
		"policy": map[string]any{
			"product": map[string]any{
				"name": "test-product",
			},
		},
		"rootOfTrust": map[string]any{
			"productLine": "test-line",
		},
		"pcrConfig": map[string]any{
			"pcrValues": map[string]any{
				"sha256": map[string]string{
					"0": "0000000000000000000000000000000000000000000000000000000000000000",
				},
			},
		},
	}

	validPolicyData, err := json.Marshal(validPolicy)
	require.NoError(t, err)

	validPolicyPath := filepath.Join(tempDir, "valid_policy.json")
	err = os.WriteFile(validPolicyPath, validPolicyData, 0o644)
	require.NoError(t, err)

	tests := []struct {
		name        string
		policyPath  string
		expectError bool
		expectedErr error
	}{
		{
			name:        "Valid policy file",
			policyPath:  validPolicyPath,
			expectError: false,
		},
		{
			name:        "Non-existent policy file",
			policyPath:  "/nonexistent/path",
			expectError: true,
			expectedErr: ErrAttestationPolicyOpen,
		},
		{
			name:        "Empty policy path",
			policyPath:  "",
			expectError: true,
			expectedErr: ErrAttestationPolicyMissing,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &attestation.Config{
				Config:    &check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}},
				PcrConfig: &attestation.PcrConfig{},
			}

			err := ReadPolicy(tt.policyPath, config)
			if tt.expectError {
				assert.Error(t, err)
				if tt.expectedErr != nil {
					assert.True(t, errors.Contains(err, tt.expectedErr))
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestReadPolicyFromByte(t *testing.T) {
	tests := []struct {
		name        string
		policyData  []byte
		expectError bool
		expectedErr error
	}{
		{
			name: "Valid policy data",
			policyData: []byte(`{
				"policy": {
					"product": {
						"name": "test-product"
					}
				},
				"rootOfTrust": {
					"productLine": "test-line"
				},
				"pcrConfig": {
					"pcrValues": {
						"sha256": {
							"0": "0000000000000000000000000000000000000000000000000000000000000000"
						}
					}
				}
			}`),
			expectError: false,
		},
		{
			name:        "Invalid JSON",
			policyData:  []byte(`{invalid json`),
			expectError: true,
			expectedErr: ErrAttestationPolicyDecode,
		},
		{
			name:        "Empty policy data",
			policyData:  []byte(``),
			expectError: true,
			expectedErr: ErrAttestationPolicyDecode,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &attestation.Config{
				Config:    &check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}},
				PcrConfig: &attestation.PcrConfig{},
			}

			err := ReadPolicyFromByte(tt.policyData, config)
			if tt.expectError {
				assert.Error(t, err)
				if tt.expectedErr != nil {
					assert.True(t, errors.Contains(err, tt.expectedErr))
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestConvertPolicyToJSON(t *testing.T) {
	tests := []struct {
		name        string
		config      *attestation.Config
		expectError bool
		expectedErr error
	}{
		{
			name: "Valid config",
			config: &attestation.Config{
				Config: &check.Config{
					Policy: &check.Policy{
						Product: &sevsnp.SevProduct{
							Name: sevsnp.SevProduct_SEV_PRODUCT_MILAN,
						},
					},
					RootOfTrust: &check.RootOfTrust{
						ProductLine: "Milan",
					},
				},
				PcrConfig: &attestation.PcrConfig{
					PCRValues: attestation.PcrValues{
						Sha256: map[string]string{
							"0": "0000000000000000000000000000000000000000000000000000000000000000",
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "Nil config",
			config: &attestation.Config{
				Config:    nil,
				PcrConfig: &attestation.PcrConfig{},
			},
			expectError: false,
			expectedErr: ErrProtoMarshalFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonData, err := ConvertPolicyToJSON(tt.config)
			if tt.expectError {
				assert.Error(t, err)
				if tt.expectedErr != nil {
					assert.True(t, errors.Contains(err, tt.expectedErr))
				}
				assert.Nil(t, jsonData)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, jsonData)

				var result map[string]any
				err = json.Unmarshal(jsonData, &result)
				assert.NoError(t, err)
			}
		})
	}
}

func TestVTPMVerify(t *testing.T) {
	writer := &mockWriter{}
	policy := &attestation.Config{
		Config:    &check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}},
		PcrConfig: &attestation.PcrConfig{},
	}

	tests := []struct {
		name        string
		quote       []byte
		teeNonce    []byte
		vtpmNonce   []byte
		expectError bool
	}{
		{
			name:        "Invalid quote data",
			quote:       []byte("invalid"),
			teeNonce:    []byte("tee-nonce"),
			vtpmNonce:   []byte("vtpm-nonce"),
			expectError: true,
		},
		{
			name:        "Empty quote",
			quote:       []byte{},
			teeNonce:    []byte("tee-nonce"),
			vtpmNonce:   []byte("vtpm-nonce"),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VTPMVerify(tt.quote, tt.teeNonce, tt.vtpmNonce, writer, policy)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVerifyQuote(t *testing.T) {
	writer := &mockWriter{}
	policy := &attestation.Config{
		Config:    &check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}},
		PcrConfig: &attestation.PcrConfig{},
	}

	tests := []struct {
		name        string
		quote       []byte
		vtpmNonce   []byte
		expectError bool
	}{
		{
			name:        "Invalid quote data",
			quote:       []byte("invalid"),
			vtpmNonce:   []byte("vtpm-nonce"),
			expectError: true,
		},
		{
			name:        "Empty quote",
			quote:       []byte{},
			vtpmNonce:   []byte("vtpm-nonce"),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyQuote(tt.quote, tt.vtpmNonce, writer, policy)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestWriterError(t *testing.T) {
	writer := &mockWriter{err: fmt.Errorf("write error")}
	policy := &attestation.Config{
		Config:    &check.Config{Policy: &check.Policy{}, RootOfTrust: &check.RootOfTrust{}},
		PcrConfig: &attestation.PcrConfig{},
	}

	err := VerifyQuote([]byte("invalid"), []byte("nonce"), writer, policy)
	assert.Error(t, err)
}

func TestVerifyAttestationReportMalformedSignature(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "policy")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	attestationPB, reportData := prepVerifyAttReport(t)
	err = setAttestationPolicy(attestationPB, tempDir)
	require.NoError(t, err)

	// Change random data so in the signature so the signature fails
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
	attestationPolicyFile, err := os.ReadFile("../../../scripts/attestation_policy/sev-snp/attestation_policy.json")
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
