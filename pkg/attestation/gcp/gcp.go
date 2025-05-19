// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"fmt"
	"io"

	"cloud.google.com/go/storage"
	"github.com/google/gce-tcb-verifier/proto/endorsement"
	"github.com/google/go-sev-guest/proto/check"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/tools/lib/report"
	"github.com/ultravioletrs/cocos/pkg/attestation"
	"google.golang.org/protobuf/proto"
)

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
	client, err := storage.NewClient(ctx)
	if err != nil {
		return &endorsement.VMGoldenMeasurement{}, fmt.Errorf("failed to create storage client: %v", err)
	}

	reader, err := client.Bucket(bucketName).Object(fmt.Sprintf(objectName, measurement384)).NewReader(ctx)
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

func GenerateAttestationPolicy(endorsement *endorsement.VMGoldenMeasurement, vcpuNum uint32) (*attestation.Config, error) {
	attestationPolicy := attestation.Config{PcrConfig: &attestation.PcrConfig{}, Config: &check.Config{RootOfTrust: &check.RootOfTrust{}, Policy: &check.Policy{}}}
	attestationPolicy.Config.Policy.Policy = endorsement.SevSnp.Policy
	attestationPolicy.Config.Policy.Measurement = endorsement.SevSnp.Measurements[vcpuNum]
	attestationPolicy.Config.RootOfTrust.DisallowNetwork = false
	attestationPolicy.Config.RootOfTrust.CheckCrl = true
	attestationPolicy.Config.RootOfTrust.Product = "Milan"
	attestationPolicy.Config.RootOfTrust.ProductLine = "Milan"

	return &attestationPolicy, nil
}

func DownloadOvmfFile(ctx context.Context, digest string) ([]byte, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return []byte{}, fmt.Errorf("failed to create storage client: %v", err)
	}

	reader, err := client.Bucket(bucketName).Object(fmt.Sprintf(ovmfObjectName, digest)).NewReader(ctx)
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
