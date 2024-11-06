// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package internal

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestZipDirectoryToMemory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "zip_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testFiles := map[string]string{
		"file1.txt":        "Content of file 1",
		"file2.txt":        "Content of file 2",
		"subdir/file3.txt": "Content of file 3 in subdirectory",
	}

	for path, content := range testFiles {
		fullPath := filepath.Join(tempDir, path)
		err := os.MkdirAll(filepath.Dir(fullPath), 0o755)
		if err != nil {
			t.Fatalf("Failed to create directory: %v", err)
		}
		err = os.WriteFile(fullPath, []byte(content), 0o644)
		if err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}
	}

	zipData, err := ZipDirectoryToMemory(tempDir)
	if err != nil {
		t.Fatalf("ZipDirectoryToMemory failed: %v", err)
	}

	if len(zipData) == 0 {
		t.Error("Zip data is empty")
	}

	unzipDir, err := os.MkdirTemp("", "unzip_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory for unzip: %v", err)
	}
	defer os.RemoveAll(unzipDir)

	err = UnzipFromMemory(zipData, unzipDir)
	if err != nil {
		t.Fatalf("UnzipFromMemory failed: %v", err)
	}

	for path, expectedContent := range testFiles {
		fullPath := filepath.Join(unzipDir, path)
		content, err := os.ReadFile(fullPath)
		if err != nil {
			t.Errorf("Failed to read unzipped file %s: %v", path, err)
			continue
		}
		if string(content) != expectedContent {
			t.Errorf("Content mismatch for file %s. Expected: %s, Got: %s", path, expectedContent, string(content))
		}
	}
}

func TestZipDirectoryToMemory_EmptyDirectory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "empty_zip_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	zipData, err := ZipDirectoryToMemory(tempDir)
	if err != nil {
		t.Fatalf("ZipDirectoryToMemory failed on empty directory: %v", err)
	}

	if len(zipData) == 0 {
		t.Error("Zip data is empty for an empty directory")
	}
}

func TestUnzipFromMemory_InvalidZipData(t *testing.T) {
	invalidZipData := []byte("This is not a valid zip file")
	tempDir, err := os.MkdirTemp("", "invalid_unzip_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	err = UnzipFromMemory(invalidZipData, tempDir)
	if err == nil {
		t.Error("UnzipFromMemory should fail with invalid zip data")
	}
}

func TestZipDirectoryToMemory_NonExistentDirectory(t *testing.T) {
	nonExistentDir := "/path/to/non/existent/directory"
	_, err := ZipDirectoryToMemory(nonExistentDir)
	if err == nil {
		t.Error("ZipDirectoryToMemory should fail with non-existent directory")
	}
}

func TestZipDirectoryToTempFile(t *testing.T) {
	tests := []struct {
		name        string
		setupFiles  map[string]string // map of relative path to content
		expectError bool
	}{
		{
			name: "single file",
			setupFiles: map[string]string{
				"test.txt": "hello world",
			},
			expectError: false,
		},
		{
			name: "multiple files in root",
			setupFiles: map[string]string{
				"test1.txt": "content1",
				"test2.txt": "content2",
				"test3.txt": "content3",
			},
			expectError: false,
		},
		{
			name: "nested directory structure",
			setupFiles: map[string]string{
				"file1.txt":                "root file",
				"dir1/file2.txt":           "nested file",
				"dir1/dir2/file3.txt":      "deeply nested file",
				"dir1/dir2/dir3/file4.txt": "very deeply nested file",
			},
			expectError: false,
		},
		{
			name:        "empty directory",
			setupFiles:  map[string]string{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sourceDir, err := os.MkdirTemp("", "source")
			if err != nil {
				t.Fatalf("Failed to create temp source directory: %v", err)
			}
			defer os.RemoveAll(sourceDir)

			for relPath, content := range tt.setupFiles {
				fullPath := filepath.Join(sourceDir, relPath)
				dir := filepath.Dir(fullPath)

				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatalf("Failed to create directory %s: %v", dir, err)
				}

				if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
					t.Fatalf("Failed to write file %s: %v", fullPath, err)
				}
			}

			zipFile, err := ZipDirectoryToTempFile(sourceDir)
			if err != nil {
				if !tt.expectError {
					t.Fatalf("Unexpected error: %v", err)
				}
				return
			}
			defer os.Remove(zipFile.Name())
			defer zipFile.Close()

			if tt.expectError {
				t.Fatal("Expected error but got none")
			}

			zipReader, err := zip.OpenReader(zipFile.Name())
			if err != nil {
				t.Fatalf("Failed to open zip file: %v", err)
			}
			defer zipReader.Close()

			expectedFiles := make(map[string]string)
			for path, content := range tt.setupFiles {
				expectedFiles[filepath.ToSlash(path)] = content
			}

			for _, file := range zipReader.File {
				expectedContent, exists := expectedFiles[file.Name]
				if !exists {
					t.Errorf("Unexpected file in zip: %s", file.Name)
					continue
				}

				rc, err := file.Open()
				if err != nil {
					t.Errorf("Failed to open file in zip %s: %v", file.Name, err)
					continue
				}

				content, err := io.ReadAll(rc)
				rc.Close()
				if err != nil {
					t.Errorf("Failed to read file in zip %s: %v", file.Name, err)
					continue
				}

				if string(content) != expectedContent {
					t.Errorf("File %s content mismatch: got %s, want %s", file.Name, content, expectedContent)
				}

				delete(expectedFiles, file.Name)
			}

			for path := range expectedFiles {
				t.Errorf("Missing file in zip: %s", path)
			}
		})
	}
}

func TestZipDirectoryToTempFile_InvalidInput(t *testing.T) {
	tests := []struct {
		name      string
		sourceDir string
	}{
		{
			name:      "non-existent directory",
			sourceDir: "/path/that/does/not/exist",
		},
		{
			name:      "empty path",
			sourceDir: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ZipDirectoryToTempFile(tt.sourceDir)
			if err == nil {
				t.Error("Expected error but got none")
			}
		})
	}
}
