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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/ultravioletrs/cocos/pkg/attestation/azure"
	"github.com/ultravioletrs/cocos/pkg/attestation/gcp"
	"google.golang.org/protobuf/proto"
)

func TestCLI_NewCreateCoRIMCmd(t *testing.T) {
	cli := &CLI{}
	cmd := cli.NewCreateCoRIMCmd()

	assert.NotNil(t, cmd)
	assert.Equal(t, "create-corim", cmd.Use)
	assert.True(t, cmd.HasSubCommands())

	subcmds := cmd.Commands()
	assert.Equal(t, 4, len(subcmds))

	cmdNames := make(map[string]bool)
	for _, sc := range subcmds {
		cmdNames[sc.Name()] = true
	}

	assert.True(t, cmdNames["azure"])
	assert.True(t, cmdNames["gcp"])
	assert.True(t, cmdNames["snp"])
	assert.True(t, cmdNames["tdx"])
}

func TestCLI_NewCreateCoRIMSNPCmd(t *testing.T) {
	cli := &CLI{}
	cmd := cli.NewCreateCoRIMSNPCmd()

	assert.NotNil(t, cmd)
	assert.Equal(t, "snp", cmd.Use)

	// Test with minimal flags
	var outBuf bytes.Buffer
	cmd.SetOut(&outBuf)
	cmd.SetErr(&outBuf)
	cmd.SetArgs([]string{"--measurement", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"})

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, outBuf.Bytes())
}

func TestCLI_NewCreateCoRIMTDXCmd(t *testing.T) {
	cli := &CLI{}
	cmd := cli.NewCreateCoRIMTDXCmd()

	assert.NotNil(t, cmd)
	assert.Equal(t, "tdx", cmd.Use)

	// Test with minimal flags
	var outBuf bytes.Buffer
	cmd.SetOut(&outBuf)
	cmd.SetErr(&outBuf)
	cmd.SetArgs([]string{"--measurement", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"})

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, outBuf.Bytes())
}

func TestCLI_NewCreateCoRIMAzureCmd_Error(t *testing.T) {
	cli := &CLI{}
	cmd := cli.NewCreateCoRIMAzureCmd()

	// Missing token flag
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	assert.Error(t, err)

	// Non-existent token file
	cmd.SetArgs([]string{"--token", "non-existent-file"})
	err = cmd.Execute()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read token file")
}

func TestCLI_NewCreateCoRIMGCPCmd_Error(t *testing.T) {
	cli := &CLI{}
	cmd := cli.NewCreateCoRIMGCPCmd()

	// Missing measurement flag
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	assert.Error(t, err)

	// GCP command will fail because it tries to call Google Cloud Storage
	cmd.SetArgs([]string{"--measurement", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"})
	err = cmd.Execute()
	assert.Error(t, err)
	// It should fail at GetLaunchEndorsement or storage client creation
}

func TestCLI_NewCreateCoRIMAzureCmd_Success(t *testing.T) {
	cli := &CLI{}
	cmd := cli.NewCreateCoRIMAzureCmd()

	oldValidator := azure.DefaultValidator
	defer func() { azure.DefaultValidator = oldValidator }()

	azure.DefaultValidator = &mockTokenValidator{
		validateFunc: func(token string) (map[string]any, error) {
			return map[string]any{
				"x-ms-isolation-tee": map[string]any{
					"x-ms-sevsnpvm-launchmeasurement": "00112233",
					"x-ms-sevsnpvm-guestsvn":          1.0,
				},
			}, nil
		},
	}

	tmpDir := t.TempDir()
	tokenPath := filepath.Join(tmpDir, "token.jwt")
	// Dummy token
	dummyToken := "eyJhbGciOiJub25lIn0.eyJoZWFkZXIiOiJkYXRhIn0."
	err := os.WriteFile(tokenPath, []byte(dummyToken), 0o644)
	require.NoError(t, err)

	var outBuf bytes.Buffer
	cmd.SetOut(&outBuf)
	cmd.SetErr(&outBuf)
	cmd.SetArgs([]string{"--token", tokenPath})

	err = cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, outBuf.Bytes())
}

type mockTokenValidator struct {
	validateFunc func(token string) (map[string]any, error)
}

func (m *mockTokenValidator) Validate(token string) (map[string]any, error) {
	return m.validateFunc(token)
}

func TestCLI_NewCreateCoRIMGCPCmd_Success(t *testing.T) {
	cli := &CLI{}
	cmd := cli.NewCreateCoRIMGCPCmd()

	oldNewStorageClient := gcp.NewStorageClient
	defer func() { gcp.NewStorageClient = oldNewStorageClient }()

	gcp.NewStorageClient = func(ctx context.Context) (gcp.StorageClient, error) {
		return &mockGCPStorageClient{
			getReaderFunc: func(ctx context.Context, bucket, object string) (io.ReadCloser, error) {
				goldenUEFI := &endorsement.VMGoldenMeasurement{
					SevSnp: &endorsement.VMSevSnp{
						Policy:       123,
						Measurements: map[uint32][]byte{1: {0x1, 0x2}},
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

	var outBuf bytes.Buffer
	cmd.SetOut(&outBuf)
	cmd.SetErr(&outBuf)
	cmd.SetArgs([]string{"--measurement", "00112233", "--vcpu", "1"})

	err := cmd.Execute()
	assert.NoError(t, err)
	assert.NotEmpty(t, outBuf.Bytes())
}

type mockGCPStorageClient struct {
	getReaderFunc func(ctx context.Context, bucket, object string) (io.ReadCloser, error)
	closeFunc     func() error
}

func (m *mockGCPStorageClient) GetReader(ctx context.Context, bucket, object string) (io.ReadCloser, error) {
	return m.getReaderFunc(ctx, bucket, object)
}

func (m *mockGCPStorageClient) Close() error {
	return m.closeFunc()
}
