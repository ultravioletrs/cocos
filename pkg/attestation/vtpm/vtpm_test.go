// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package vtpm

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/corim/comid"
	"github.com/veraison/corim/corim"
	"google.golang.org/protobuf/proto"
)

type mockTPM struct {
	*bytes.Buffer
	closeErr error
}

func (m *mockTPM) Close() error {
	return m.closeErr
}

type errorRWC struct {
	DummyRWC
}

func (e *errorRWC) Write(p []byte) (int, error) {
	return 0, fmt.Errorf("write error")
}

func (e *errorRWC) Read(p []byte) (int, error) {
	return 0, fmt.Errorf("read error")
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

func TestAttest(t *testing.T) {
	originalExternalTPM := ExternalTPM
	defer func() { ExternalTPM = originalExternalTPM }()

	ExternalTPM = &mockTPM{Buffer: &bytes.Buffer{}}

	_, err := Attest([]byte("tee-nonce"), []byte("vtpm-nonce"), false, 0)
	assert.Error(t, err)
}

func TestExtendPCR(t *testing.T) {
	originalExternalTPM := ExternalTPM
	defer func() { ExternalTPM = originalExternalTPM }()

	ExternalTPM = &errorRWC{}

	err := ExtendPCR(PCR16, []byte("test-value"))
	assert.Error(t, err)
}

func TestGetPCRValue(t *testing.T) {
	originalExternalTPM := ExternalTPM
	defer func() { ExternalTPM = originalExternalTPM }()

	ExternalTPM = &DummyRWC{}

	val, err := GetPCRSHA1Value(PCR15)
	assert.NoError(t, err)
	assert.Len(t, val, 20)

	val, err = GetPCRSHA256Value(PCR15)
	assert.NoError(t, err)
	assert.Len(t, val, 20)

	val, err = GetPCRSHA384Value(PCR15)
	assert.NoError(t, err)
	assert.Len(t, val, 20)
}

func TestVerifier_VerifyWithCoRIM(t *testing.T) {
	v := NewVerifier(&mockWriter{})

	// 1. Invalid report
	err := v.VerifyWithCoRIM([]byte("invalid"), &corim.UnsignedCorim{})
	assert.Error(t, err)

	// 2. Missing SEV-SNP attestation
	att := &attest.Attestation{}
	reportBytes, _ := proto.Marshal(att)
	err = v.VerifyWithCoRIM(reportBytes, &corim.UnsignedCorim{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no SEV-SNP attestation found")

	// 3. No measurement in report
	att = &attest.Attestation{
		TeeAttestation: &attest.Attestation_SevSnpAttestation{
			SevSnpAttestation: &sevsnp.Attestation{
				Report: &sevsnp.Report{},
			},
		},
	}
	reportBytes, _ = proto.Marshal(att)
	err = v.VerifyWithCoRIM(reportBytes, &corim.UnsignedCorim{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no measurement in SEV-SNP report")

	// 4. Successful match
	measurement := []byte("test-measurement-1234")
	att = &attest.Attestation{
		TeeAttestation: &attest.Attestation_SevSnpAttestation{
			SevSnpAttestation: &sevsnp.Attestation{
				Report: &sevsnp.Report{
					Measurement: measurement,
				},
			},
		},
	}
	reportBytes, _ = proto.Marshal(att)

	// Create a mock CoMID with the same measurement
	c := comid.NewComid()
	m := comid.MustNewUintMeasurement(uint64(1))
	m.AddDigest(1, measurement)
	c.AddReferenceValue(comid.ReferenceValue{
		Measurements: comid.Measurements{*m},
	})

	unsignedCorim := corim.NewUnsignedCorim()
	unsignedCorim.AddComid(*c)

	err = v.VerifyWithCoRIM(reportBytes, unsignedCorim)
	assert.NoError(t, err)

	// 5. CoRIM with no tags
	unsignedCorim.Tags = nil
	err = v.VerifyWithCoRIM(reportBytes, unsignedCorim)
	assert.NoError(t, err) // Matches current implementation behavior

	// 6. Non-CoMID tag
	unsignedCorim.Tags = []corim.Tag{corim.Tag([]byte("non-comid-tag"))}
	err = v.VerifyWithCoRIM(reportBytes, unsignedCorim)
	assert.NoError(t, err)

	// 7. Invalid CoMID tag
	unsignedCorim.Tags = []corim.Tag{corim.Tag(append(corim.ComidTag, []byte("invalid")...))}
	err = v.VerifyWithCoRIM(reportBytes, unsignedCorim)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse CoMID from tag")
}
