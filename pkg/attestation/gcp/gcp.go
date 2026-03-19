// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"

	"cloud.google.com/go/storage"
	"github.com/google/gce-tcb-verifier/proto/endorsement"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/tools/lib/report"
	"google.golang.org/protobuf/proto"
)

// StorageClient defines the interface for Google Cloud Storage operations.
type StorageClient interface {
	GetReader(ctx context.Context, bucket, object string) (io.ReadCloser, error)
	Close() error
}

type gcpStorageClient struct {
	client *storage.Client
}

func (c *gcpStorageClient) GetReader(ctx context.Context, bucket, object string) (io.ReadCloser, error) {
	return c.client.Bucket(bucket).Object(object).NewReader(ctx)
}

func (c *gcpStorageClient) Close() error {
	return c.client.Close()
}

var NewStorageClient = func(ctx context.Context) (StorageClient, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, err
	}
	return &gcpStorageClient{client: client}, nil
}

const (
	// Offset of the 384-bit measurement in the report.
	// The measurement is 48 bytes long and starts at offset 0x90.
	// https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf page 56
	measurementOffset = 0x90
	measurementSize   = 48
	bucketName        = "gce_tcb_integrity"
	objectName        = "ovmf_x64_csm/sevsnp/%s.binarypb"
	ovmfObjectName    = "ovmf_x64_csm/%s.fd"
)

func Extract384BitMeasurement(attestation *sevsnp.Attestation) (string, error) {
	if attestation == nil {
		return "", fmt.Errorf("report is nil")
	}

	reportBin, err := report.Transform(attestation, "bin")
	if err != nil {
		return "", fmt.Errorf("failed to transform report to binary: %v", err)
	}

	if len(reportBin) < measurementOffset+measurementSize {
		return "", fmt.Errorf("report is too short to contain the 384-bit measurement")
	}

	measurement := reportBin[measurementOffset : measurementOffset+measurementSize]
	return fmt.Sprintf("%x", measurement), nil
}

func GetLaunchEndorsement(ctx context.Context, measurement384 string) (*endorsement.VMGoldenMeasurement, error) {
	client, err := NewStorageClient(ctx)
	if err != nil {
		return &endorsement.VMGoldenMeasurement{}, fmt.Errorf("failed to create storage client: %v", err)
	}
	defer client.Close()

	reader, err := client.GetReader(ctx, bucketName, fmt.Sprintf(objectName, measurement384))
	if err != nil {
		return &endorsement.VMGoldenMeasurement{}, fmt.Errorf("failed to create reader: %v", err)
	}
	defer reader.Close()

	launchEndorsements, err := io.ReadAll(reader)
	if err != nil {
		return &endorsement.VMGoldenMeasurement{}, fmt.Errorf("failed to read object: %v", err)
	}

	var endorsementPB endorsement.VMLaunchEndorsement
	if err := proto.Unmarshal(launchEndorsements, &endorsementPB); err != nil {
		return &endorsement.VMGoldenMeasurement{}, fmt.Errorf("failed to unmarshal launch endorsement: %v", err)
	}

	var goldenUEFI endorsement.VMGoldenMeasurement
	if err := proto.Unmarshal(endorsementPB.SerializedUefiGolden, &goldenUEFI); err != nil {
		return &endorsement.VMGoldenMeasurement{}, fmt.Errorf("failed to unmarshal golden UEFI: %v", err)
	}

	return &goldenUEFI, nil
}

func DownloadOvmfFile(ctx context.Context, digest string) ([]byte, error) {
	client, err := NewStorageClient(ctx)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to create storage client: %v", err)
	}
	defer client.Close()

	reader, err := client.GetReader(ctx, bucketName, fmt.Sprintf(ovmfObjectName, digest))
	if err != nil {
		return []byte{}, fmt.Errorf("failed to create reader: %v", err)
	}
	defer reader.Close()

	ovmf, err := io.ReadAll(reader)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to read object: %v", err)
	}

	return ovmf, nil
}

// GCPMeasurementData contains the exact fields extracted from a GCP VM Golden Measurement
// needed to construct a CoRIM policy for the SNP platform.
type GCPMeasurementData struct {
	Measurement string
	Policy      uint64
}

// ExtractGCPMeasurement extracts the core SNP measurements from a GCP Endorsement for a specific vCPU count.
func ExtractGCPMeasurement(endorsement *endorsement.VMGoldenMeasurement, vcpuNum uint32) (*GCPMeasurementData, error) {
	if endorsement.SevSnp == nil {
		return nil, fmt.Errorf("endorsement does not contain SEV-SNP data")
	}

	measurementBytes, ok := endorsement.SevSnp.Measurements[vcpuNum]
	if !ok {
		return nil, fmt.Errorf("endorsement does not contain measurement for vCPU %d", vcpuNum)
	}

	return &GCPMeasurementData{
		Measurement: hex.EncodeToString(measurementBytes),
		Policy:      endorsement.SevSnp.Policy,
	}, nil
}
