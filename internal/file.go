// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package internal

import (
	"encoding/hex"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/sha3"
)

// CopyFile copies a file from srcPath to dstPath.
func CopyFile(srcPath, dstPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	if err != nil {
		return err
	}

	return nil
}

// DeleteFilesInDir deletes all files in the directory dirPath.
func DeleteFilesInDir(dirPath string) error {
	files, err := filepath.Glob(filepath.Join(dirPath, "*"))
	if err != nil {
		return err
	}

	for _, file := range files {
		err := os.Remove(file)
		if err != nil {
			return err
		}
	}

	return nil
}

// Checksum calculates the SHA3-256 checksum of the file or directory at path.
func Checksum(path string) ([]byte, error) {
	_, sum, err := Digest(path)
	return sum, err
}

// Digest returns the data used for checksumming and the checksum itself.
func Digest(path string) ([]byte, []byte, error) {
	file, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}

	var data []byte
	if file.IsDir() {
		data, err = ZipDirectoryToMemory(path)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, nil, err
	}

	sum := sha3.Sum256(data)
	return data, sum[:], nil
}

// ChecksumHex calculates the SHA3-256 checksum of the file or directory at path and returns it as a hex-encoded string.
func ChecksumHex(path string) (string, error) {
	sum, err := Checksum(path)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sum), nil
}
