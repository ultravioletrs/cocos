// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"archive/tar"
	"bytes"
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

const testPythonScript = "print('hello')"

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
		ociDir, destDir := setupTestOCIImage(t, "algorithm.py", testPythonScript)
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

func TestExtractDatasetWithPathTraversal(t *testing.T) {
	t.Run("path traversal skipped, valid file extracted", func(t *testing.T) {
		ociDir := t.TempDir()
		destDir := t.TempDir()

		blobsDir := filepath.Join(ociDir, "blobs", "sha256")
		require.NoError(t, os.MkdirAll(blobsDir, 0o755))

		layerPath := filepath.Join(blobsDir, "layer123")
		layerFile, err := os.Create(layerPath)
		require.NoError(t, err)

		gw := gzip.NewWriter(layerFile)
		tw := tar.NewWriter(gw)

		// Path traversal entry (should be skipped)
		maliciousHdr := &tar.Header{
			Name: "../../../tmp/evil.csv",
			Mode: 0o644,
			Size: int64(len("evil")),
		}
		require.NoError(t, tw.WriteHeader(maliciousHdr))
		_, err = tw.Write([]byte("evil"))
		require.NoError(t, err)

		// Valid CSV file
		csvContent := "col1,col2\n1,2"
		csvHdr := &tar.Header{
			Name: "data.csv",
			Mode: 0o644,
			Size: int64(len(csvContent)),
		}
		require.NoError(t, tw.WriteHeader(csvHdr))
		_, err = tw.Write([]byte(csvContent))
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
		require.NoError(t, os.WriteFile(filepath.Join(blobsDir, "manifest123"), manifestData, 0o644))

		index := OCIIndex{
			SchemaVersion: 2,
			Manifests: []struct {
				MediaType string `json:"mediaType"`
				Digest    string `json:"digest"`
				Size      int    `json:"size"`
			}{{Digest: "sha256:manifest123", Size: len(manifestData)}},
		}
		indexData, _ := json.Marshal(index)
		require.NoError(t, os.WriteFile(filepath.Join(ociDir, "index.json"), indexData, 0o644))

		files, err := ExtractDataset(ociDir, destDir)
		require.NoError(t, err)
		assert.Len(t, files, 1)
		assert.Contains(t, files[0], "data.csv")

		// Verify malicious file was NOT created outside destDir
		_, err = os.Stat("/tmp/evil.csv")
		assert.True(t, os.IsNotExist(err))
	})
}

func TestExtractDatasetInvalidManifest(t *testing.T) {
	t.Run("invalid manifest JSON", func(t *testing.T) {
		ociDir := t.TempDir()
		blobsDir := filepath.Join(ociDir, "blobs", "sha256")
		require.NoError(t, os.MkdirAll(blobsDir, 0o755))

		require.NoError(t, os.WriteFile(filepath.Join(blobsDir, "manifest123"), []byte("not json"), 0o644))

		index := OCIIndex{
			SchemaVersion: 2,
			Manifests: []struct {
				MediaType string `json:"mediaType"`
				Digest    string `json:"digest"`
				Size      int    `json:"size"`
			}{{Digest: "sha256:manifest123", Size: 8}},
		}
		indexData, _ := json.Marshal(index)
		require.NoError(t, os.WriteFile(filepath.Join(ociDir, "index.json"), indexData, 0o644))

		_, err := ExtractDataset(ociDir, t.TempDir())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse manifest")
	})
}

func TestExtractDatasetWithDirectory(t *testing.T) {
	t.Run("layer with directory entries for dataset", func(t *testing.T) {
		ociDir := t.TempDir()
		destDir := t.TempDir()

		blobsDir := filepath.Join(ociDir, "blobs", "sha256")
		require.NoError(t, os.MkdirAll(blobsDir, 0o755))

		layerPath := filepath.Join(blobsDir, "layer123")
		layerFile, err := os.Create(layerPath)
		require.NoError(t, err)

		gw := gzip.NewWriter(layerFile)
		tw := tar.NewWriter(gw)

		// Directory entry
		dirHdr := &tar.Header{
			Name:     "data/",
			Mode:     0o755,
			Typeflag: tar.TypeDir,
		}
		require.NoError(t, tw.WriteHeader(dirHdr))

		// CSV inside directory
		csvContent := "a,b\n1,2"
		csvHdr := &tar.Header{
			Name: "data/dataset.csv",
			Mode: 0o644,
			Size: int64(len(csvContent)),
		}
		require.NoError(t, tw.WriteHeader(csvHdr))
		_, err = tw.Write([]byte(csvContent))
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
		require.NoError(t, os.WriteFile(filepath.Join(blobsDir, "manifest123"), manifestData, 0o644))

		index := OCIIndex{
			SchemaVersion: 2,
			Manifests: []struct {
				MediaType string `json:"mediaType"`
				Digest    string `json:"digest"`
				Size      int    `json:"size"`
			}{{Digest: "sha256:manifest123", Size: len(manifestData)}},
		}
		indexData, _ := json.Marshal(index)
		require.NoError(t, os.WriteFile(filepath.Join(ociDir, "index.json"), indexData, 0o644))

		files, err := ExtractDataset(ociDir, destDir)
		require.NoError(t, err)
		require.Len(t, files, 1)
		assert.Contains(t, files[0], "dataset.csv")
	})
}

func TestExtractDatasetMissingManifest(t *testing.T) {
	t.Run("manifest file not found", func(t *testing.T) {
		ociDir := t.TempDir()
		blobsDir := filepath.Join(ociDir, "blobs", "sha256")
		require.NoError(t, os.MkdirAll(blobsDir, 0o755))

		index := OCIIndex{
			SchemaVersion: 2,
			Manifests: []struct {
				MediaType string `json:"mediaType"`
				Digest    string `json:"digest"`
				Size      int    `json:"size"`
			}{{Digest: "sha256:nonexistent", Size: 0}},
		}
		indexData, _ := json.Marshal(index)
		require.NoError(t, os.WriteFile(filepath.Join(ociDir, "index.json"), indexData, 0o644))

		_, err := ExtractDataset(ociDir, t.TempDir())
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read manifest")
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
	manifestData, err := json.Marshal(manifest)
	require.NoError(t, err)
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
	indexData, err := json.Marshal(index)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(ociDir, "index.json"), indexData, 0o644))

	return ociDir, destDir
}

func TestExtractAlgorithmWithRequirements(t *testing.T) {
	logger := slog.Default()

	t.Run("extract algorithm with requirements.txt", func(t *testing.T) {
		ociDir := t.TempDir()
		destDir := t.TempDir()

		blobsDir := filepath.Join(ociDir, "blobs", "sha256")
		require.NoError(t, os.MkdirAll(blobsDir, 0o755))

		layerPath := filepath.Join(blobsDir, "layer123")
		layerFile, err := os.Create(layerPath)
		require.NoError(t, err)

		gw := gzip.NewWriter(layerFile)
		tw := tar.NewWriter(gw)

		// Add algorithm file
		algoContent := testPythonScript
		algoHdr := &tar.Header{
			Name: "main.py",
			Mode: 0o644,
			Size: int64(len(algoContent)),
		}
		require.NoError(t, tw.WriteHeader(algoHdr))
		_, err = tw.Write([]byte(algoContent))
		require.NoError(t, err)

		// Add requirements.txt
		reqContent := "numpy==1.21.0\npandas==1.3.0"
		reqHdr := &tar.Header{
			Name: "requirements.txt",
			Mode: 0o644,
			Size: int64(len(reqContent)),
		}
		require.NoError(t, tw.WriteHeader(reqHdr))
		_, err = tw.Write([]byte(reqContent))
		require.NoError(t, err)

		require.NoError(t, tw.Close())
		require.NoError(t, gw.Close())
		require.NoError(t, layerFile.Close())

		// Create manifest and index
		manifest := struct {
			Layers []struct {
				Digest string `json:"digest"`
			} `json:"layers"`
		}{
			Layers: []struct {
				Digest string `json:"digest"`
			}{{Digest: "sha256:layer123"}},
		}
		manifestData, err := json.Marshal(manifest)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(blobsDir, "manifest123"), manifestData, 0o644))

		index := OCIIndex{
			SchemaVersion: 2,
			Manifests: []struct {
				MediaType string `json:"mediaType"`
				Digest    string `json:"digest"`
				Size      int    `json:"size"`
			}{{Digest: "sha256:manifest123", Size: len(manifestData)}},
		}
		indexData, err := json.Marshal(index)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(ociDir, "index.json"), indexData, 0o644))

		algoPath, err := ExtractAlgorithm(context.Background(), logger, ociDir, destDir)
		require.NoError(t, err)
		assert.Contains(t, algoPath, "main.py")

		// Verify requirements.txt was also extracted
		reqPath := filepath.Join(destDir, "requirements.txt")
		_, err = os.Stat(reqPath)
		assert.NoError(t, err)
	})
}

func TestExtractAlgorithmNoAlgoFile(t *testing.T) {
	logger := slog.Default()

	t.Run("no algorithm file in layers", func(t *testing.T) {
		ociDir := t.TempDir()
		destDir := t.TempDir()

		blobsDir := filepath.Join(ociDir, "blobs", "sha256")
		require.NoError(t, os.MkdirAll(blobsDir, 0o755))

		layerPath := filepath.Join(blobsDir, "layer123")
		layerFile, err := os.Create(layerPath)
		require.NoError(t, err)

		gw := gzip.NewWriter(layerFile)
		tw := tar.NewWriter(gw)

		// Add a non-algorithm file (e.g., just a readme)
		readmeContent := "This is a readme"
		readmeHdr := &tar.Header{
			Name: "README.md",
			Mode: 0o644,
			Size: int64(len(readmeContent)),
		}
		require.NoError(t, tw.WriteHeader(readmeHdr))
		_, err = tw.Write([]byte(readmeContent))
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
		require.NoError(t, os.WriteFile(filepath.Join(blobsDir, "manifest123"), manifestData, 0o644))

		index := OCIIndex{
			SchemaVersion: 2,
			Manifests: []struct {
				MediaType string `json:"mediaType"`
				Digest    string `json:"digest"`
				Size      int    `json:"size"`
			}{{Digest: "sha256:manifest123", Size: len(manifestData)}},
		}
		indexData, _ := json.Marshal(index)
		require.NoError(t, os.WriteFile(filepath.Join(ociDir, "index.json"), indexData, 0o644))

		_, err = ExtractAlgorithm(context.Background(), logger, ociDir, destDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no algorithm file found")
	})
}

func TestExtractDatasetNoDataFiles(t *testing.T) {
	t.Run("no data files in layers", func(t *testing.T) {
		ociDir := t.TempDir()
		destDir := t.TempDir()

		blobsDir := filepath.Join(ociDir, "blobs", "sha256")
		require.NoError(t, os.MkdirAll(blobsDir, 0o755))

		layerPath := filepath.Join(blobsDir, "layer123")
		layerFile, err := os.Create(layerPath)
		require.NoError(t, err)

		gw := gzip.NewWriter(layerFile)
		tw := tar.NewWriter(gw)

		// Add a python file (not a data file)
		pyContent := testPythonScript
		pyHdr := &tar.Header{
			Name: "script.py",
			Mode: 0o644,
			Size: int64(len(pyContent)),
		}
		require.NoError(t, tw.WriteHeader(pyHdr))
		_, err = tw.Write([]byte(pyContent))
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
		require.NoError(t, os.WriteFile(filepath.Join(blobsDir, "manifest123"), manifestData, 0o644))

		index := OCIIndex{
			SchemaVersion: 2,
			Manifests: []struct {
				MediaType string `json:"mediaType"`
				Digest    string `json:"digest"`
				Size      int    `json:"size"`
			}{{Digest: "sha256:manifest123", Size: len(manifestData)}},
		}
		indexData, _ := json.Marshal(index)
		require.NoError(t, os.WriteFile(filepath.Join(ociDir, "index.json"), indexData, 0o644))

		_, err = ExtractDataset(ociDir, destDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no dataset files found")
	})
}

func TestExtractAlgorithmInvalidManifest(t *testing.T) {
	logger := slog.Default()

	t.Run("invalid manifest JSON", func(t *testing.T) {
		ociDir := t.TempDir()
		destDir := t.TempDir()

		blobsDir := filepath.Join(ociDir, "blobs", "sha256")
		require.NoError(t, os.MkdirAll(blobsDir, 0o755))

		// Write invalid manifest
		require.NoError(t, os.WriteFile(filepath.Join(blobsDir, "manifest123"), []byte("not json"), 0o644))

		index := OCIIndex{
			SchemaVersion: 2,
			Manifests: []struct {
				MediaType string `json:"mediaType"`
				Digest    string `json:"digest"`
				Size      int    `json:"size"`
			}{{Digest: "sha256:manifest123", Size: 8}},
		}
		indexData, _ := json.Marshal(index)
		require.NoError(t, os.WriteFile(filepath.Join(ociDir, "index.json"), indexData, 0o644))

		_, err := ExtractAlgorithm(context.Background(), logger, ociDir, destDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse manifest")
	})
}

func TestExtractAlgorithmMissingManifest(t *testing.T) {
	logger := slog.Default()

	t.Run("manifest file not found", func(t *testing.T) {
		ociDir := t.TempDir()
		destDir := t.TempDir()

		blobsDir := filepath.Join(ociDir, "blobs", "sha256")
		require.NoError(t, os.MkdirAll(blobsDir, 0o755))

		// Don't create manifest file
		index := OCIIndex{
			SchemaVersion: 2,
			Manifests: []struct {
				MediaType string `json:"mediaType"`
				Digest    string `json:"digest"`
				Size      int    `json:"size"`
			}{{Digest: "sha256:missing123", Size: 8}},
		}
		indexData, _ := json.Marshal(index)
		require.NoError(t, os.WriteFile(filepath.Join(ociDir, "index.json"), indexData, 0o644))

		_, err := ExtractAlgorithm(context.Background(), logger, ociDir, destDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read manifest")
	})
}

func TestExtractAlgorithmWithDirectory(t *testing.T) {
	logger := slog.Default()

	t.Run("layer with directory entries", func(t *testing.T) {
		ociDir := t.TempDir()
		destDir := t.TempDir()

		blobsDir := filepath.Join(ociDir, "blobs", "sha256")
		require.NoError(t, os.MkdirAll(blobsDir, 0o755))

		layerPath := filepath.Join(blobsDir, "layer123")
		layerFile, err := os.Create(layerPath)
		require.NoError(t, err)

		gw := gzip.NewWriter(layerFile)
		tw := tar.NewWriter(gw)

		// Add a directory entry
		dirHdr := &tar.Header{
			Name:     "src/",
			Mode:     0o755,
			Typeflag: tar.TypeDir,
		}
		require.NoError(t, tw.WriteHeader(dirHdr))

		// Add algorithm file in subdirectory
		algoContent := testPythonScript
		algoHdr := &tar.Header{
			Name: "src/main.py",
			Mode: 0o644,
			Size: int64(len(algoContent)),
		}
		require.NoError(t, tw.WriteHeader(algoHdr))
		_, err = tw.Write([]byte(algoContent))
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
		require.NoError(t, os.WriteFile(filepath.Join(blobsDir, "manifest123"), manifestData, 0o644))

		index := OCIIndex{
			SchemaVersion: 2,
			Manifests: []struct {
				MediaType string `json:"mediaType"`
				Digest    string `json:"digest"`
				Size      int    `json:"size"`
			}{{Digest: "sha256:manifest123", Size: len(manifestData)}},
		}
		indexData, _ := json.Marshal(index)
		require.NoError(t, os.WriteFile(filepath.Join(ociDir, "index.json"), indexData, 0o644))

		algoPath, err := ExtractAlgorithm(context.Background(), logger, ociDir, destDir)
		require.NoError(t, err)
		assert.Contains(t, algoPath, "main.py")
	})
}

func TestExtractAlgorithmPathTraversal(t *testing.T) {
	logger := slog.Default()

	t.Run("path traversal attempt", func(t *testing.T) {
		ociDir := t.TempDir()
		destDir := t.TempDir()

		blobsDir := filepath.Join(ociDir, "blobs", "sha256")
		require.NoError(t, os.MkdirAll(blobsDir, 0o755))

		layerPath := filepath.Join(blobsDir, "layer123")
		layerFile, err := os.Create(layerPath)
		require.NoError(t, err)

		gw := gzip.NewWriter(layerFile)
		tw := tar.NewWriter(gw)

		// Add a file with path traversal attempt
		maliciousContent := "malicious"
		maliciousHdr := &tar.Header{
			Name: "../../../etc/malicious.py",
			Mode: 0o644,
			Size: int64(len(maliciousContent)),
		}
		require.NoError(t, tw.WriteHeader(maliciousHdr))
		_, err = tw.Write([]byte(maliciousContent))
		require.NoError(t, err)

		// Add a legit file
		algoContent := testPythonScript
		algoHdr := &tar.Header{
			Name: "algorithm.py",
			Mode: 0o644,
			Size: int64(len(algoContent)),
		}
		require.NoError(t, tw.WriteHeader(algoHdr))
		_, err = tw.Write([]byte(algoContent))
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
		require.NoError(t, os.WriteFile(filepath.Join(blobsDir, "manifest123"), manifestData, 0o644))

		index := OCIIndex{
			SchemaVersion: 2,
			Manifests: []struct {
				MediaType string `json:"mediaType"`
				Digest    string `json:"digest"`
				Size      int    `json:"size"`
			}{{Digest: "sha256:manifest123", Size: len(manifestData)}},
		}
		indexData, _ := json.Marshal(index)
		require.NoError(t, os.WriteFile(filepath.Join(ociDir, "index.json"), indexData, 0o644))

		algoPath, err := ExtractAlgorithm(context.Background(), logger, ociDir, destDir)
		require.NoError(t, err)
		assert.Contains(t, algoPath, "algorithm.py")

		// Verify malicious file was NOT extracted outside destDir
		_, err = os.Stat("/etc/malicious.py")
		assert.True(t, os.IsNotExist(err))
	})
}

func TestExtractAlgorithmErrorPathsAdditional(t *testing.T) {
	logger := slog.Default()

	t.Run("invalid layer gzip", func(t *testing.T) {
		ociDir, destDir := setupTestOCIImage(t, "main.py", "print('hello')")
		// Corrupt the layer file
		layerPath := filepath.Join(ociDir, "blobs", "sha256", "layer123")
		err := os.WriteFile(layerPath, []byte("not gzip"), 0o644)
		require.NoError(t, err)

		_, err = ExtractAlgorithm(context.Background(), logger, ociDir, destDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no algorithm file found")
	})

	t.Run("invalid tar formatting", func(t *testing.T) {
		ociDir, destDir := setupTestOCIImage(t, "main.py", "print('hello')")
		layerPath := filepath.Join(ociDir, "blobs", "sha256", "layer123")

		// Create a valid gzip but invalid tar
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		_, err := gw.Write([]byte("not a tar archive but it is gzipped"))
		require.NoError(t, err)
		gw.Close()
		err = os.WriteFile(layerPath, buf.Bytes(), 0o644)
		require.NoError(t, err)

		_, err = ExtractAlgorithm(context.Background(), logger, ociDir, destDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no algorithm file found")
	})

	t.Run("non-existent layer file", func(t *testing.T) {
		ociDir := t.TempDir()
		destDir := t.TempDir()
		blobsDir := filepath.Join(ociDir, "blobs", "sha256")
		require.NoError(t, os.MkdirAll(blobsDir, 0o755))

		manifest := struct {
			Layers []struct {
				Digest string `json:"digest"`
			} `json:"layers"`
		}{
			Layers: []struct {
				Digest string `json:"digest"`
			}{{Digest: "sha256:nonexistent"}},
		}
		manifestData, _ := json.Marshal(manifest)
		require.NoError(t, os.WriteFile(filepath.Join(blobsDir, "manifest123"), manifestData, 0o644))

		index := OCIIndex{
			SchemaVersion: 2,
			Manifests: []struct {
				MediaType string `json:"mediaType"`
				Digest    string `json:"digest"`
				Size      int    `json:"size"`
			}{{Digest: "sha256:manifest123", Size: len(manifestData)}},
		}
		indexData, _ := json.Marshal(index)
		require.NoError(t, os.WriteFile(filepath.Join(ociDir, "index.json"), indexData, 0o644))

		_, err := ExtractAlgorithm(context.Background(), logger, ociDir, destDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no algorithm file found")
	})
}

func TestExtractDatasetErrorPathsAdditional(t *testing.T) {
	t.Run("invalid layer gzip", func(t *testing.T) {
		ociDir, destDir := setupTestOCIImage(t, "data.csv", "a,b,c")
		layerPath := filepath.Join(ociDir, "blobs", "sha256", "layer123")
		err := os.WriteFile(layerPath, []byte("not gzip"), 0o644)
		require.NoError(t, err)

		_, err = ExtractDataset(ociDir, destDir)
		assert.Error(t, err)
	})

	t.Run("non-existent layer file", func(t *testing.T) {
		ociDir := t.TempDir()
		destDir := t.TempDir()
		blobsDir := filepath.Join(ociDir, "blobs", "sha256")
		require.NoError(t, os.MkdirAll(blobsDir, 0o755))

		manifest := struct {
			Layers []struct {
				Digest string `json:"digest"`
			} `json:"layers"`
		}{
			Layers: []struct {
				Digest string `json:"digest"`
			}{{Digest: "sha256:nonexistent"}},
		}
		manifestData, _ := json.Marshal(manifest)
		require.NoError(t, os.WriteFile(filepath.Join(blobsDir, "manifest123"), manifestData, 0o644))

		index := OCIIndex{
			SchemaVersion: 2,
			Manifests: []struct {
				MediaType string `json:"mediaType"`
				Digest    string `json:"digest"`
				Size      int    `json:"size"`
			}{{Digest: "sha256:manifest123", Size: len(manifestData)}},
		}
		indexData, _ := json.Marshal(index)
		require.NoError(t, os.WriteFile(filepath.Join(ociDir, "index.json"), indexData, 0o644))

		_, err := ExtractDataset(ociDir, destDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no dataset files found")
	})
}
