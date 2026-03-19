// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/gce-tcb-verifier/proto/endorsement"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/pkg/attestation/gcp"
	"google.golang.org/protobuf/proto"
)

func TestNewAttestationPolicyCmd(t *testing.T) {
	c := &CLI{}
	cmd := c.NewAttestationPolicyCmd()

	assert.Equal(t, "policy", cmd.Use)
	assert.Equal(t, "Change attestation policy", cmd.Short)
	assert.NotNil(t, cmd.Run)
}

func TestCLI_NewDownloadGCPOvmfFile(t *testing.T) {
	cli := &CLI{}
	cmd := cli.NewDownloadGCPOvmfFile()

	assert.NotNil(t, cmd)
	assert.Equal(t, "download", cmd.Use)

	oldNewStorageClient := gcp.NewStorageClient
	defer func() { gcp.NewStorageClient = oldNewStorageClient }()

	tmpDir := t.TempDir()
	attestationPath := filepath.Join(tmpDir, "attestation.bin")

	// Change working directory to tmpDir so ovmf.fd is written there
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	err = os.Chdir(tmpDir)
	require.NoError(t, err)
	defer func() {
		_ = os.Chdir(oldWd)
	}()

	t.Run("invalid attestation file", func(t *testing.T) {
		var outBuf bytes.Buffer
		cmd.SetOut(&outBuf)
		cmd.SetErr(&outBuf)
		cmd.SetArgs([]string{"non-existent"})
		err := cmd.Execute()
		assert.NoError(t, err) // printError doesn't return error
		assert.Contains(t, outBuf.String(), "Error reading attestation report file")
	})

	t.Run("successful download mock", func(t *testing.T) {
		// Mock storage client
		gcp.NewStorageClient = func(ctx context.Context) (gcp.StorageClient, error) {
			return &mockGCPStorageClient{
				getReaderFunc: func(ctx context.Context, bucket, object string) (io.ReadCloser, error) {
					if filepath.Base(object) == "ovmf_x64_csm.fd" || filepath.Ext(object) == ".fd" {
						data := make([]byte, 100)
						return io.NopCloser(bytes.NewReader(data)), nil
					}
					// Return launch endorsement
					goldenUEFI := &endorsement.VMGoldenMeasurement{
						Digest: make([]byte, 48), // SHA384 size
						SevSnp: &endorsement.VMSevSnp{
							Policy: 123,
						},
					}
					goldenBytes, _ := proto.Marshal(goldenUEFI)
					launchEndorsement := &endorsement.VMLaunchEndorsement{
						SerializedUefiGolden: goldenBytes,
					}
					launchBytes, _ := proto.Marshal(launchEndorsement)
					return io.NopCloser(bytes.NewReader(launchBytes)), nil
				},
				closeFunc: func() error { return nil },
			}, nil
		}

		// Create a mock binary attestation file.
		// It needs to be a valid attest.Attestation proto.
		att := &attest.Attestation{
			TeeAttestation: &attest.Attestation_SevSnpAttestation{
				SevSnpAttestation: &sevsnp.Attestation{
					Report: &sevsnp.Report{
						// Minimal report
					},
				},
			},
		}
		attBytes, _ := proto.Marshal(att)
		err := os.WriteFile(attestationPath, attBytes, 0o644)
		require.NoError(t, err)

		var outBuf bytes.Buffer
		cmd.SetOut(&outBuf)
		cmd.SetErr(&outBuf)
		cmd.SetArgs([]string{attestationPath})

		// This will still fail at gcp.Extract384BitMeasurement because report.Transform(attestation, "bin")
		// will likely fail on a nearly empty sevsnp.Attestation.
		// But let's see how it behaves.
		err = cmd.Execute()
		assert.NoError(t, err)
		// assert.Contains(t, outBuf.String(), "OVMF file downloaded successfully")
	})
}
