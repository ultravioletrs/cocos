// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSkopeoClient(t *testing.T) {
	t.Run("valid work directory", func(t *testing.T) {
		workDir := t.TempDir()
		client, err := NewSkopeoClient(workDir)
		if err != nil && err.Error() == "skopeo not found in PATH: exec: \"skopeo\": executable file not found in $PATH" {
			t.Skip("skopeo not installed, skipping test")
		}
		require.NoError(t, err)
		assert.NotNil(t, client)
	})

	t.Run("new work directory", func(t *testing.T) {
		workDir := filepath.Join(t.TempDir(), "new", "nested", "dir")
		client, err := NewSkopeoClient(workDir)
		if err != nil && err.Error() == "skopeo not found in PATH: exec: \"skopeo\": executable file not found in $PATH" {
			t.Skip("skopeo not installed, skipping test")
		}
		require.NoError(t, err)
		assert.NotNil(t, client)
	})
}

func TestSkopeoClient_GetLocalImagePath(t *testing.T) {
	workDir := t.TempDir()
	client, err := NewSkopeoClient(workDir)
	if err != nil {
		t.Skip("skopeo not installed, skipping test")
	}

	tests := []struct {
		name     string
		imgName  string
		expected string
	}{
		{"simple image name", "myimage", filepath.Join(workDir, "myimage")},
		{"image with tag", "myimage:latest", filepath.Join(workDir, "myimage:latest")},
		{"nested path", "registry/repo/image", filepath.Join(workDir, "registry/repo/image")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := client.GetLocalImagePath(tt.imgName)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestSkopeoClient_PullAndDecrypt(t *testing.T) {
	workDir := t.TempDir()
	client, err := NewSkopeoClient(workDir)
	if err != nil {
		t.Skip("skopeo not installed, skipping test")
	}

	t.Run("invalid source URI", func(t *testing.T) {
		ctx := context.Background()
		destDir := t.TempDir()
		source := ResourceSource{
			Type:      ResourceTypeOCIImage,
			URI:       "invalid://not-a-valid-uri",
			Encrypted: false,
		}
		err := client.PullAndDecrypt(ctx, source, destDir)
		assert.Error(t, err)
	})

	t.Run("destination directory created", func(t *testing.T) {
		ctx := context.Background()
		destDir := filepath.Join(t.TempDir(), "new", "nested", "dest")
		source := ResourceSource{
			Type:      ResourceTypeOCIImage,
			URI:       "invalid://test",
			Encrypted: false,
		}
		_ = client.PullAndDecrypt(ctx, source, destDir)
		_, err := os.Stat(destDir)
		assert.NoError(t, err)
	})
}

func TestSkopeoClient_Inspect(t *testing.T) {
	workDir := t.TempDir()
	client, err := NewSkopeoClient(workDir)
	if err != nil {
		t.Skip("skopeo not installed, skipping test")
	}

	t.Run("invalid image reference", func(t *testing.T) {
		ctx := context.Background()
		manifest, err := client.Inspect(ctx, "invalid://not-a-valid-ref")
		assert.Error(t, err)
		assert.Nil(t, manifest)
	})
}

func TestResourceSource(t *testing.T) {
	t.Run("ResourceType constants", func(t *testing.T) {
		assert.Equal(t, ResourceType("oci-image"), ResourceTypeOCIImage)
	})

	t.Run("ResourceSource structure", func(t *testing.T) {
		source := ResourceSource{
			Type:            ResourceTypeOCIImage,
			URI:             "docker://registry/repo:tag",
			Encrypted:       true,
			KBSResourcePath: "default/key/algo-key",
		}
		assert.Equal(t, ResourceTypeOCIImage, source.Type)
		assert.Equal(t, "docker://registry/repo:tag", source.URI)
		assert.True(t, source.Encrypted)
		assert.Equal(t, "default/key/algo-key", source.KBSResourcePath)
	})
}

func TestImageManifest(t *testing.T) {
	t.Run("ImageManifest structure", func(t *testing.T) {
		manifest := ImageManifest{
			Reference: "docker://registry/repo:tag",
			Digest:    "sha256:abc123",
			Layers:    []string{"sha256:layer1", "sha256:layer2"},
		}
		assert.Equal(t, "docker://registry/repo:tag", manifest.Reference)
		assert.Equal(t, "sha256:abc123", manifest.Digest)
		assert.Len(t, manifest.Layers, 2)
	})
}

func TestSkopeoConstants(t *testing.T) {
	assert.Equal(t, "OCICRYPT_KEYPROVIDER_CONFIG", OCICryptKeyproviderConfig)
	assert.Equal(t, "/etc/ocicrypt_keyprovider.conf", DefaultOCICryptConfig)
	assert.Equal(t, "provider:attestation-agent:cc_kbc::null", DecryptionKeyProvider)
}
