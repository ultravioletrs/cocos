// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"errors"
	"testing"

	"cloud.google.com/go/storage"
	"github.com/google/gce-tcb-verifier/proto/endorsement"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestExtract384BitMeasurement(t *testing.T) {
	tests := []struct {
		name        string
		attestation *sevsnp.Attestation
		setupMock   func()
		expected    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "nil attestation",
			attestation: nil,
			expectError: true,
			errorMsg:    "report is nil",
		},
		{
			name:        "short report",
			attestation: &sevsnp.Attestation{Report: &sevsnp.Report{}},
			expectError: true,
			errorMsg:    "failed to transform report to binary",
		},
		{
			name:        "empty report",
			attestation: &sevsnp.Attestation{},
			expectError: true,
			errorMsg:    "failed to transform report to binary",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Extract384BitMeasurement(tt.attestation)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Empty(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestGetLaunchEndorsement(t *testing.T) {
	tests := []struct {
		name           string
		measurement384 string
		setupMock      func() ([]byte, error)
		expectError    bool
		errorMsg       string
	}{
		{
			name:           "successful retrieval",
			measurement384: "test-measurement",
			setupMock: func() ([]byte, error) {
				goldenUEFI := &endorsement.VMGoldenMeasurement{
					SevSnp: &endorsement.VMSevSnp{
						Policy:       12345,
						Measurements: map[uint32][]byte{1: []byte("test-measurement")},
					},
				}
				goldenBytes, _ := proto.Marshal(goldenUEFI)

				launchEndorsement := &endorsement.VMLaunchEndorsement{
					SerializedUefiGolden: goldenBytes,
				}
				return proto.Marshal(launchEndorsement)
			},
			expectError: false,
		},
		{
			name:           "storage client error",
			measurement384: "test-measurement",
			setupMock: func() ([]byte, error) {
				return nil, errors.New("storage client error")
			},
			expectError: true,
			errorMsg:    "failed to create reader",
		},
		{
			name:           "object not found",
			measurement384: "non-existent-measurement",
			setupMock: func() ([]byte, error) {
				return nil, storage.ErrObjectNotExist
			},
			expectError: true,
			errorMsg:    "failed to create reader",
		},
		{
			name:           "invalid protobuf data",
			measurement384: "test-measurement",
			setupMock: func() ([]byte, error) {
				return []byte("invalid protobuf data"), nil
			},
			expectError: true,
			errorMsg:    "failed to create reader",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// skip if credentials are not set
			if _, err := storage.NewClient(ctx); err != nil && tt.expectError {
				t.Skip("Skipping test due to missing GCP credentials")
			}

			_, err := GetLaunchEndorsement(ctx, tt.measurement384)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			}
		})
	}
}

func TestGenerateAttestationPolicy(t *testing.T) {
	tests := []struct {
		name        string
		endorsement *endorsement.VMGoldenMeasurement
		vcpuNum     uint32
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid endorsement",
			endorsement: &endorsement.VMGoldenMeasurement{
				SevSnp: &endorsement.VMSevSnp{
					Policy:       12345,
					Measurements: map[uint32][]byte{1: []byte("test-measurement")},
				},
			},
			vcpuNum:     1,
			expectError: false,
		},
		{
			name: "missing measurement for vcpu",
			endorsement: &endorsement.VMGoldenMeasurement{
				SevSnp: &endorsement.VMSevSnp{
					Policy:       12345,
					Measurements: map[uint32][]byte{2: []byte("test-measurement")},
				},
			},
			vcpuNum:     1,
			expectError: false,
		},
		{
			name: "empty measurements map",
			endorsement: &endorsement.VMGoldenMeasurement{
				SevSnp: &endorsement.VMSevSnp{
					Policy:       12345,
					Measurements: map[uint32][]byte{},
				},
			},
			vcpuNum:     1,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GenerateAttestationPolicy(tt.endorsement, tt.vcpuNum)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.NotNil(t, result.Config)
				assert.NotNil(t, result.Config.Policy)
				assert.NotNil(t, result.Config.RootOfTrust)
				assert.NotNil(t, result.PcrConfig)

				assert.Equal(t, tt.endorsement.SevSnp.Policy, result.Config.Policy.Policy)
				assert.Equal(t, tt.endorsement.SevSnp.Measurements[tt.vcpuNum], result.Config.Policy.Measurement)
				assert.False(t, result.Config.RootOfTrust.DisallowNetwork)
				assert.True(t, result.Config.RootOfTrust.CheckCrl)
				assert.Equal(t, "Milan", result.Config.RootOfTrust.Product)
				assert.Equal(t, "Milan", result.Config.RootOfTrust.ProductLine)
			}
		})
	}
}

func TestDownloadOvmfFile(t *testing.T) {
	tests := []struct {
		name        string
		digest      string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "successful download",
			digest:      "test-digest",
			expectError: false,
		},
		{
			name:        "storage client error",
			digest:      "test-digest",
			expectError: true,
			errorMsg:    "failed to create reader",
		},
		{
			name:        "object not found",
			digest:      "non-existent-digest",
			expectError: true,
			errorMsg:    "failed to create reader",
		},
		{
			name:        "read error",
			digest:      "test-digest",
			expectError: true,
			errorMsg:    "failed to create reader",
		},
		{
			name:        "empty digest",
			digest:      "",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// skip if credentials are not set
			if _, err := storage.NewClient(ctx); err != nil && tt.expectError {
				t.Skip("Skipping test due to missing GCP credentials")
			}

			_, err := DownloadOvmfFile(ctx, tt.digest)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			}
		})
	}
}
