// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsAlgorithmFile(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     bool
	}{
		{"Python file", "algorithm.py", true},
		{"WASM file", "module.wasm", true},
		{"WAT file", "module.wat", true},
		{"JavaScript file", "script.js", true},
		{"Shell script", "run.sh", true},
		{"Main python file", "main.py", true},
		{"Execute file", "execute.py", true},
		{"Algorithm name in path", "src/algorithm_v2.py", true},
		{"Random python file", "helper.py", true},
		{"CSV data file", "data.csv", false},
		{"JSON config file", "config.json", false},
		{"Text file", "readme.txt", false},
		{"Binary file", "data.bin", false},
		{"Uppercase extension", "MAIN.PY", true},
		{"Mixed case", "Algorithm.Py", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAlgorithmFile(tt.filename)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsDataFile(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     bool
	}{
		{"CSV file", "data.csv", true},
		{"JSON file", "config.json", true},
		{"Text file", "readme.txt", true},
		{"Parquet file", "data.parquet", true},
		{"Arrow file", "data.arrow", true},
		{"DAT file", "data.dat", true},
		{"Python file", "script.py", false},
		{"WASM file", "module.wasm", false},
		{"Binary file", "data.bin", false},
		{"Uppercase CSV", "DATA.CSV", true},
		{"Nested path", "data/input/dataset.csv", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDataFile(tt.filename)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractAlgorithm(t *testing.T) {
	logger := slog.Default()

	t.Run("missing index.json", func(t *testing.T) {
		tempDir := t.TempDir()
		_, err := ExtractAlgorithm(context.Background(), logger, tempDir, t.TempDir())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read index.json")
	})

	t.Run("invalid index.json", func(t *testing.T) {
		tempDir := t.TempDir()
		err := os.WriteFile(filepath.Join(tempDir, "index.json"), []byte("not json"), 0o644)
		require.NoError(t, err)

		_, err = ExtractAlgorithm(context.Background(), logger, tempDir, t.TempDir())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse index.json")
	})

	t.Run("empty manifests", func(t *testing.T) {
		tempDir := t.TempDir()
		index := OCIIndex{SchemaVersion: 2}
		data, _ := json.Marshal(index)
		err := os.WriteFile(filepath.Join(tempDir, "index.json"), data, 0o644)
		require.NoError(t, err)

		_, err = ExtractAlgorithm(context.Background(), logger, tempDir, t.TempDir())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no manifests found")
	})

	t.Run("successful extraction", func(t *testing.T) {
		ociDir, destDir := setupTestOCIImage(t, "algorithm.py", "print('hello')")
		algoPath, err := ExtractAlgorithm(context.Background(), logger, ociDir, destDir)
		require.NoError(t, err)
		assert.NotEmpty(t, algoPath)
		assert.Contains(t, algoPath, "algorithm.py")
	})
}

func TestExtractDataset(t *testing.T) {
	t.Run("missing index.json", func(t *testing.T) {
		tempDir := t.TempDir()
		_, err := ExtractDataset(tempDir, t.TempDir())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read index.json")
	})

	t.Run("successful extraction", func(t *testing.T) {
		ociDir, destDir := setupTestOCIImage(t, "data.csv", "col1,col2\n1,2")
		files, err := ExtractDataset(ociDir, destDir)
		require.NoError(t, err)
		assert.NotEmpty(t, files)
	})
}

func TestOCILayoutStructure(t *testing.T) {
	t.Run("OCILayout JSON serialization", func(t *testing.T) {
		layout := OCILayout{ImageLayoutVersion: "1.0.0"}

		data, err := json.Marshal(layout)
		require.NoError(t, err)

		var decoded OCILayout
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, layout.ImageLayoutVersion, decoded.ImageLayoutVersion)
	})
}

func setupTestOCIImage(t *testing.T, filename, content string) (ociDir, destDir string) {
	t.Helper()

	ociDir = t.TempDir()
	destDir = t.TempDir()

	blobsDir := filepath.Join(ociDir, "blobs", "sha256")
	require.NoError(t, os.MkdirAll(blobsDir, 0o755))

	layerPath := filepath.Join(blobsDir, "layer123")
	layerFile, err := os.Create(layerPath)
	require.NoError(t, err)

	gw := gzip.NewWriter(layerFile)
	tw := tar.NewWriter(gw)

	hdr := &tar.Header{
		Name: filename,
		Mode: 0o644,
		Size: int64(len(content)),
	}
	require.NoError(t, tw.WriteHeader(hdr))
	_, err = tw.Write([]byte(content))
	require.NoError(t, err)

	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
	require.NoError(t, layerFile.Close())

	manifest := struct {
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}{
		Layers: []struct {
			Digest string `json:"digest"`
		}{{Digest: "sha256:layer123"}},
	}
	manifestData, _ := json.Marshal(manifest)
	manifestPath := filepath.Join(blobsDir, "manifest123")
	require.NoError(t, os.WriteFile(manifestPath, manifestData, 0o644))

	index := OCIIndex{
		SchemaVersion: 2,
		Manifests: []struct {
			MediaType string `json:"mediaType"`
			Digest    string `json:"digest"`
			Size      int    `json:"size"`
		}{{
			MediaType: "application/vnd.oci.image.manifest.v1+json",
			Digest:    "sha256:manifest123",
			Size:      len(manifestData),
		}},
	}
	indexData, _ := json.Marshal(index)
	require.NoError(t, os.WriteFile(filepath.Join(ociDir, "index.json"), indexData, 0o644))

	return ociDir, destDir
}
