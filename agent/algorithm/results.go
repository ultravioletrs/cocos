// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package algorithm

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ZipDirectory zips a directory and returns the zipped bytes.
func ZipDirectory() ([]byte, error) {
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	err := filepath.Walk(ResultsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("error walking the path %q: %v", path, err)
		}

		if info.IsDir() {
			return nil
		}

		relPath, err := filepath.Rel(ResultsDir, path)
		if err != nil {
			return fmt.Errorf("error getting relative path for %q: %v", path, err)
		}

		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("error opening file %q: %v", path, err)
		}
		defer file.Close()

		zipFile, err := zipWriter.Create(relPath)
		if err != nil {
			return fmt.Errorf("error creating zip file for %q: %v", path, err)
		}

		if _, err = io.Copy(zipFile, file); err != nil {
			return fmt.Errorf("error copying file %q to zip: %v", path, err)
		}

		return err
	})
	if err != nil {
		return nil, err
	}

	if err = zipWriter.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
