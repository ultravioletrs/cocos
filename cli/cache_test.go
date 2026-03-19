// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"os"
	"path"
	"testing"

	"github.com/google/go-sev-guest/verify/trust"
	"github.com/stretchr/testify/assert"
)

var _ trust.HTTPSGetter = (*mockGetter)(nil)

type mockGetter struct {
	content []byte
}

func (m *mockGetter) Get(url string) ([]byte, error) {
	return m.content, nil
}

func TestNewCABundleCmd(t *testing.T) {
	cli := &CLI{}
	tempDir, err := os.MkdirTemp("", "ca-bundle-test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	product := "Milan"
	bundleContent := []byte("test ca bundle content")
	mock := &mockGetter{content: bundleContent}

	cmd := cli.NewCABundleCmd(tempDir, mock)
	cmd.SetArgs([]string{product})
	output := &bytes.Buffer{}
	cmd.SetOutput(output)
	err = cmd.Execute()

	assert.NoError(t, err)

	expectedFilePath := path.Join(tempDir, product, caBundleName)
	_, err = os.Stat(expectedFilePath)
	assert.NoError(t, err)

	content, err := os.ReadFile(expectedFilePath)
	assert.NoError(t, err)
	assert.Equal(t, bundleContent, content)
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
