// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestCLI_NewCreateCoRIMSNPCmd_OutputFile(t *testing.T) {
	cli := &CLI{}
	cmd := cli.NewCreateCoRIMSNPCmd()

	tmpDir, err := os.MkdirTemp("", "corim-test-")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	outputPath := filepath.Join(tmpDir, "policy.cbor")
	cmd.SetArgs([]string{"--measurement", "00", "--output", outputPath})

	err = cmd.Execute()
	assert.NoError(t, err)

	_, err = os.Stat(outputPath)
	assert.NoError(t, err)
}
