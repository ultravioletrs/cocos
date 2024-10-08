// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewCABundleCmd(t *testing.T) {
	cli := &CLI{}
	tempDir, err := os.MkdirTemp("", "ca-bundle-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	manifestContent := []byte(`{"root_of_trust": {"product": "Milan"}}`)
	manifestPath := path.Join(tempDir, "manifest.json")
	err = os.WriteFile(manifestPath, manifestContent, 0o644)
	assert.NoError(t, err)

	cmd := cli.NewCABundleCmd(tempDir)
	cmd.SetArgs([]string{manifestPath})
	output := &bytes.Buffer{}
	cmd.SetOutput(output)
	err = cmd.Execute()

	assert.NoError(t, err)

	expectedFilePath := path.Join(tempDir, "Milan", caBundleName)
	_, err = os.Stat(expectedFilePath)
	assert.NoError(t, err)

	content, err := os.ReadFile(expectedFilePath)
	assert.NoError(t, err)
	assert.NotNil(t, content)
}

func TestSaveToFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "save-to-file-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	filePath := path.Join(tempDir, "test-file.txt")
	content := []byte("test content")

	err = saveToFile(filePath, content)
	assert.NoError(t, err)

	savedContent, err := os.ReadFile(filePath)
	assert.NoError(t, err)
	assert.Equal(t, content, savedContent)

	_, err = os.Stat(filePath)
	assert.NoError(t, err)
}
