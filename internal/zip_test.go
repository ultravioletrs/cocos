package internal

import (
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
		err := os.MkdirAll(filepath.Dir(fullPath), 0755)
		if err != nil {
			t.Fatalf("Failed to create directory: %v", err)
		}
		err = os.WriteFile(fullPath, []byte(content), 0644)
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
