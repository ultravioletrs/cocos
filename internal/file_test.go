// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package internal

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestCopyFile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "copyfile_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	srcPath := filepath.Join(tempDir, "source.txt")
	content := []byte("Hello, World!")
	if err := os.WriteFile(srcPath, content, 0o644); err != nil {
		t.Fatalf("Failed to create source file: %v", err)
	}

	dstPath := filepath.Join(tempDir, "destination.txt")
	if err := CopyFile(srcPath, dstPath); err != nil {
		t.Fatalf("CopyFile failed: %v", err)
	}

	copiedContent, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatalf("Failed to read destination file: %v", err)
	}

	if !bytes.Equal(content, copiedContent) {
		t.Errorf("Copied content does not match original. Got %s, want %s", copiedContent, content)
	}
}

func TestCopyFile_NonExistentSource(t *testing.T) {
	err := CopyFile("nonexistent.txt", "destination.txt")
	if err == nil {
		t.Error("CopyFile did not return an error for a nonexistent source file")
	}
}

func TestDeleteFilesInDir(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "deletefiles_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	filenames := []string{"file1.txt", "file2.txt", "file3.txt"}
	for _, filename := range filenames {
		filepath := filepath.Join(tempDir, filename)
		if err := os.WriteFile(filepath, []byte("test"), 0o644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	if err := DeleteFilesInDir(tempDir); err != nil {
		t.Fatalf("DeleteFilesInDir failed: %v", err)
	}

	remainingFiles, err := os.ReadDir(tempDir)
	if err != nil {
		t.Fatalf("Failed to read directory: %v", err)
	}

	if len(remainingFiles) != 0 {
		t.Errorf("Directory not empty after deletion. %d files remain", len(remainingFiles))
	}
}

func TestChecksum(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "checksum_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	filePath := filepath.Join(tempDir, "test.txt")
	content := []byte("Hello, World!")
	if err := os.WriteFile(filePath, content, 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	checksum, err := Checksum(filePath)
	if err != nil {
		t.Fatalf("Checksum failed: %v", err)
	}

	expectedChecksum, _ := hex.DecodeString("1af17a664e3fa8e419b8ba05c2a173169df76162a5a286e0c405b460d478f7ef")
	if !bytes.Equal(checksum, expectedChecksum) {
		t.Errorf("File checksum mismatch. Got %x, want %x", checksum, expectedChecksum)
	}

	dirPath := filepath.Join(tempDir, "testdir")
	if err := os.Mkdir(dirPath, 0o755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dirPath, "file1.txt"), []byte("File 1"), 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dirPath, "file2.txt"), []byte("File 2"), 0o644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	dirChecksum, err := Checksum(dirPath)
	if err != nil {
		t.Fatalf("Directory Checksum failed: %v", err)
	}

	if len(dirChecksum) != 32 { // SHA3-256 produces a 32-byte hash
		t.Errorf("Unexpected directory checksum length. Got %d bytes, want 32 bytes", len(dirChecksum))
	}
}

func TestChecksum_NonExistentFile(t *testing.T) {
	_, err := Checksum("nonexistent.txt")
	if err == nil {
		t.Error("Checksum did not return an error for a nonexistent file")
	}
}

func TestChecksumHex(t *testing.T) {
	tempFile, err := os.CreateTemp("", "checksumhex_test")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	content := []byte("Hello, World!")
	if _, err := tempFile.Write(content); err != nil {
		t.Fatalf("Failed to write to test file: %v", err)
	}
	tempFile.Close()

	checksumHex, err := ChecksumHex(tempFile.Name())
	if err != nil {
		t.Fatalf("ChecksumHex failed: %v", err)
	}

	expectedChecksumHex := "1af17a664e3fa8e419b8ba05c2a173169df76162a5a286e0c405b460d478f7ef"
	if checksumHex != expectedChecksumHex {
		t.Errorf("ChecksumHex mismatch. Got %s, want %s", checksumHex, expectedChecksumHex)
	}
}

func TestChecksumHex_NonExistentFile(t *testing.T) {
	_, err := ChecksumHex("nonexistent.txt")
	if err == nil {
		t.Error("ChecksumHex did not return an error for a nonexistent file")
	}
}
