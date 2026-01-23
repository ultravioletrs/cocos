// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// OCILayout represents the OCI image layout
type OCILayout struct {
	ImageLayoutVersion string `json:"imageLayoutVersion"`
}

// OCIIndex represents the OCI index.json
type OCIIndex struct {
	SchemaVersion int `json:"schemaVersion"`
	Manifests     []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int    `json:"size"`
	} `json:"manifests"`
}

// ExtractAlgorithm extracts the algorithm file from an OCI image directory
func ExtractAlgorithm(ociDir, destPath string) (string, error) {
	// Read index.json to find manifest
	indexPath := filepath.Join(ociDir, "index.json")
	indexData, err := os.ReadFile(indexPath)
	if err != nil {
		return "", fmt.Errorf("failed to read index.json: %w", err)
	}

	var index OCIIndex
	if err := json.Unmarshal(indexData, &index); err != nil {
		return "", fmt.Errorf("failed to parse index.json: %w", err)
	}

	if len(index.Manifests) == 0 {
		return "", fmt.Errorf("no manifests found in index.json")
	}

	// Get the first manifest digest
	manifestDigest := index.Manifests[0].Digest
	manifestPath := filepath.Join(ociDir, "blobs", strings.Replace(manifestDigest, ":", "/", 1))

	// Read manifest to find layers
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return "", fmt.Errorf("failed to read manifest: %w", err)
	}

	var manifest struct {
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return "", fmt.Errorf("failed to parse manifest: %w", err)
	}

	// Extract layers to find algorithm files
	for _, layer := range manifest.Layers {
		layerPath := filepath.Join(ociDir, "blobs", strings.Replace(layer.Digest, ":", "/", 1))

		// Try to extract and find algorithm file
		algoPath, err := extractLayerAndFindAlgorithm(layerPath, destPath)
		if err == nil && algoPath != "" {
			return algoPath, nil
		}
	}

	return "", fmt.Errorf("no algorithm file found in OCI image layers")
}

// extractLayerAndFindAlgorithm extracts a layer and searches for algorithm files
func extractLayerAndFindAlgorithm(layerPath, destPath string) (string, error) {
	// Open layer file
	layerFile, err := os.Open(layerPath)
	if err != nil {
		return "", err
	}
	defer layerFile.Close()

	// Decompress gzip
	gzReader, err := gzip.NewReader(layerFile)
	if err != nil {
		return "", err
	}
	defer gzReader.Close()

	// Read tar archive
	tarReader := tar.NewReader(gzReader)

	var algorithmPath string

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}

		// Skip directories
		if header.Typeflag == tar.TypeDir {
			continue
		}

		// Check if this is an algorithm file
		if isAlgorithmFile(header.Name) {
			// Extract to destination
			targetPath := filepath.Join(destPath, filepath.Base(header.Name))

			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return "", err
			}

			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return "", err
			}

			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return "", err
			}
			outFile.Close()

			algorithmPath = targetPath
			// Continue to extract all algorithm files, but return the first one found
		}
	}

	return algorithmPath, nil
}

// isAlgorithmFile checks if a file is likely an algorithm file
func isAlgorithmFile(filename string) bool {
	// Common algorithm file extensions
	algorithmExts := []string{".py", ".wasm", ".wat", ".js", ".sh"}

	// Common algorithm file names
	algorithmNames := []string{"algorithm", "main", "run", "execute"}

	base := filepath.Base(filename)
	baseLower := strings.ToLower(base)

	// Check extensions
	for _, ext := range algorithmExts {
		if strings.HasSuffix(baseLower, ext) {
			return true
		}
	}

	// Check common names
	for _, name := range algorithmNames {
		if strings.Contains(baseLower, name) {
			return true
		}
	}

	return false
}

// ExtractDataset extracts dataset files from an OCI image directory
func ExtractDataset(ociDir, destPath string) ([]string, error) {
	// Similar to ExtractAlgorithm but extracts all data files
	// Read index.json to find manifest
	indexPath := filepath.Join(ociDir, "index.json")
	indexData, err := os.ReadFile(indexPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read index.json: %w", err)
	}

	var index OCIIndex
	if err := json.Unmarshal(indexData, &index); err != nil {
		return nil, fmt.Errorf("failed to parse index.json: %w", err)
	}

	if len(index.Manifests) == 0 {
		return nil, fmt.Errorf("no manifests found in index.json")
	}

	// Get the first manifest digest
	manifestDigest := index.Manifests[0].Digest
	manifestPath := filepath.Join(ociDir, "blobs", strings.Replace(manifestDigest, ":", "/", 1))

	// Read manifest to find layers
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %w", err)
	}

	var manifest struct {
		Layers []struct {
			Digest string `json:"digest"`
		} `json:"layers"`
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse manifest: %w", err)
	}

	var datasetFiles []string

	// Extract all layers and collect dataset files
	for _, layer := range manifest.Layers {
		layerPath := filepath.Join(ociDir, "blobs", strings.Replace(layer.Digest, ":", "/", 1))

		files, err := extractLayerDataFiles(layerPath, destPath)
		if err == nil {
			datasetFiles = append(datasetFiles, files...)
		}
	}

	if len(datasetFiles) == 0 {
		return nil, fmt.Errorf("no dataset files found in OCI image layers")
	}

	return datasetFiles, nil
}

// extractLayerDataFiles extracts data files from a layer
func extractLayerDataFiles(layerPath, destPath string) ([]string, error) {
	layerFile, err := os.Open(layerPath)
	if err != nil {
		return nil, err
	}
	defer layerFile.Close()

	gzReader, err := gzip.NewReader(layerFile)
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()

	tarReader := tar.NewReader(gzReader)
	var extractedFiles []string

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if header.Typeflag == tar.TypeDir {
			continue
		}

		// Check if this is a data file
		if isDataFile(header.Name) {
			targetPath := filepath.Join(destPath, filepath.Base(header.Name))

			if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
				return nil, err
			}

			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return nil, err
			}

			if _, err := io.Copy(outFile, tarReader); err != nil {
				outFile.Close()
				return nil, err
			}
			outFile.Close()

			extractedFiles = append(extractedFiles, targetPath)
		}
	}

	return extractedFiles, nil
}

// isDataFile checks if a file is likely a dataset file
func isDataFile(filename string) bool {
	dataExts := []string{".csv", ".json", ".txt", ".parquet", ".arrow", ".dat"}

	baseLower := strings.ToLower(filepath.Base(filename))

	for _, ext := range dataExts {
		if strings.HasSuffix(baseLower, ext) {
			return true
		}
	}

	return false
}
