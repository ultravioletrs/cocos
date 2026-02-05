// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package vtpm

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
