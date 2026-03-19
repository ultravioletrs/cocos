// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/google/gce-tcb-verifier/proto/endorsement"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

type mockStorageClient struct {
	getReaderFunc func(ctx context.Context, bucket, object string) (io.ReadCloser, error)
	closeFunc     func() error
}

func (m *mockStorageClient) GetReader(ctx context.Context, bucket, object string) (io.ReadCloser, error) {
	if m.getReaderFunc != nil {
		return m.getReaderFunc(ctx, bucket, object)
	}
	return nil, errors.New("GetReader not implemented")
}

func (m *mockStorageClient) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

type errorReader struct{}

func (e *errorReader) Read(p []byte) (int, error) {
	return 0, errors.New("read error")
}

func (e *errorReader) Close() error {
	return nil
}

func TestExtract384BitMeasurement(t *testing.T) {
	tests := []struct {
		name        string
		attestation *sevsnp.Attestation
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
			name:        "invalid attestation",
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
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestGetLaunchEndorsement(t *testing.T) {
	oldNewStorageClient := NewStorageClient
	defer func() { NewStorageClient = oldNewStorageClient }()

	tests := []struct {
		name           string
		measurement384 string
		mockClient     *mockStorageClient
		clientErr      error
		expectError    bool
		errorMsg       string
	}{
		{
			name:           "successful retrieval",
			measurement384: "test-measurement",
			mockClient: &mockStorageClient{
				getReaderFunc: func(ctx context.Context, bucket, object string) (io.ReadCloser, error) {
					goldenUEFI := &endorsement.VMGoldenMeasurement{
						SevSnp: &endorsement.VMSevSnp{
							Policy: 12345,
						},
					}
					goldenBytes, _ := proto.Marshal(goldenUEFI)
					launchEndorsement := &endorsement.VMLaunchEndorsement{
						SerializedUefiGolden: goldenBytes,
					}
					launchBytes, _ := proto.Marshal(launchEndorsement)
					return io.NopCloser(bytes.NewReader(launchBytes)), nil
				},
			},
			expectError: false,
		},
		{
			name:        "storage client error",
			clientErr:   errors.New("client error"),
			expectError: true,
			errorMsg:    "failed to create storage client",
		},
		{
			name: "reader error",
			mockClient: &mockStorageClient{
				getReaderFunc: func(ctx context.Context, bucket, object string) (io.ReadCloser, error) {
					return nil, errors.New("reader error")
				},
			},
			expectError: true,
			errorMsg:    "failed to create reader",
		},
		{
			name: "invalid launch endorsement protobuf",
			mockClient: &mockStorageClient{
				getReaderFunc: func(ctx context.Context, bucket, object string) (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader([]byte("invalid"))), nil
				},
			},
			expectError: true,
			errorMsg:    "failed to unmarshal launch endorsement",
		},
		{
			name: "invalid golden UEFI protobuf",
			mockClient: &mockStorageClient{
				getReaderFunc: func(ctx context.Context, bucket, object string) (io.ReadCloser, error) {
					launchEndorsement := &endorsement.VMLaunchEndorsement{
						SerializedUefiGolden: []byte("invalid"),
					}
					launchBytes, _ := proto.Marshal(launchEndorsement)
					return io.NopCloser(bytes.NewReader(launchBytes)), nil
				},
			},
			expectError: true,
			errorMsg:    "failed to unmarshal golden UEFI",
		},
		{
			name: "read error",
			mockClient: &mockStorageClient{
				getReaderFunc: func(ctx context.Context, bucket, object string) (io.ReadCloser, error) {
					return &errorReader{}, nil
				},
			},
			expectError: true,
			errorMsg:    "failed to read object",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			NewStorageClient = func(ctx context.Context) (StorageClient, error) {
				if tt.clientErr != nil {
					return nil, tt.clientErr
				}
				return tt.mockClient, nil
			}

			_, err := GetLaunchEndorsement(context.Background(), tt.measurement384)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDownloadOvmfFile(t *testing.T) {
	oldNewStorageClient := NewStorageClient
	defer func() { NewStorageClient = oldNewStorageClient }()

	tests := []struct {
		name        string
		digest      string
		mockClient  *mockStorageClient
		clientErr   error
		expectError bool
		errorMsg    string
	}{
		{
			name:   "successful download",
			digest: "test-digest",
			mockClient: &mockStorageClient{
				getReaderFunc: func(ctx context.Context, bucket, object string) (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader([]byte("ovmf-data"))), nil
				},
			},
			expectError: false,
		},
		{
			name:        "client error",
			clientErr:   errors.New("client error"),
			expectError: true,
			errorMsg:    "failed to create storage client",
		},
		{
			name: "reader error",
			mockClient: &mockStorageClient{
				getReaderFunc: func(ctx context.Context, bucket, object string) (io.ReadCloser, error) {
					return nil, errors.New("reader error")
				},
			},
			expectError: true,
			errorMsg:    "failed to create reader",
		},
		{
			name: "read error",
			mockClient: &mockStorageClient{
				getReaderFunc: func(ctx context.Context, bucket, object string) (io.ReadCloser, error) {
					return &errorReader{}, nil
				},
			},
			expectError: true,
			errorMsg:    "failed to read object",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			NewStorageClient = func(ctx context.Context) (StorageClient, error) {
				if tt.clientErr != nil {
					return nil, tt.clientErr
				}
				return tt.mockClient, nil
			}

			data, err := DownloadOvmfFile(context.Background(), tt.digest)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, []byte("ovmf-data"), data)
			}
		})
	}
}

func TestExtractGCPMeasurement(t *testing.T) {
	tests := []struct {
		name        string
		endorsement *endorsement.VMGoldenMeasurement
		vcpuNum     uint32
		expectError bool
		errorMsg    string
	}{
		{
			name: "successful extraction",
			endorsement: &endorsement.VMGoldenMeasurement{
				SevSnp: &endorsement.VMSevSnp{
					Measurements: map[uint32][]byte{1: {0x1, 0x2}},
					Policy:       123,
				},
			},
			vcpuNum:     1,
			expectError: false,
		},
		{
			name:        "missing SEV-SNP data",
			endorsement: &endorsement.VMGoldenMeasurement{},
			expectError: true,
			errorMsg:    "endorsement does not contain SEV-SNP data",
		},
		{
			name: "missing vCPU measurement",
			endorsement: &endorsement.VMGoldenMeasurement{
				SevSnp: &endorsement.VMSevSnp{
					Measurements: map[uint32][]byte{2: {0x1}},
				},
			},
			vcpuNum:     1,
			expectError: true,
			errorMsg:    "endorsement does not contain measurement for vCPU 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := ExtractGCPMeasurement(tt.endorsement, tt.vcpuNum)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, data)
				assert.Equal(t, "0102", data.Measurement)
				assert.Equal(t, uint64(123), data.Policy)
			}
		})
	}
}
