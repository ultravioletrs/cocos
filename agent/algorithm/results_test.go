// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package algorithm_test

import (
	"os"
	"testing"

	"github.com/ultravioletrs/cocos/agent/algorithm"
)

func TestZipDirectory(t *testing.T) {
	cases := []struct {
		name        string
		directories []string
		files       []string
		expected    []string
	}{
		{
			name:        "empty directory",
			directories: []string{"testdata"},
		},
		{
			name:  "single file",
			files: []string{"file1.txt"},
		},
		{
			name:        "directory with single file",
			directories: []string{"testdata"},
			expected:    []string{"testdata/file1.txt"},
		},
		{
			name:        "directory with multiple files",
			directories: []string{"testdata"},
			expected: []string{
				"testdata/file1.txt",
				"testdata/file2.txt",
				"testdata/file3.txt",
			},
		},
		{
			name:        "nested directories",
			directories: []string{"testdata", "testdata/nested"},
			expected: []string{
				"testdata/nested/file1.txt",
				"testdata/nested/file2.txt",
				"testdata/nested/file3.txt",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.Mkdir(algorithm.ResultsDir, 0o755); err != nil {
				t.Fatalf("error creating results directory: %s", err.Error())
			}
			defer func() {
				if err := os.RemoveAll(algorithm.ResultsDir); err != nil {
					t.Fatalf("error removing results directory and its contents: %s", err.Error())
				}
			}()

			for _, dir := range tc.directories {
				if dir != "" {
					if err := os.Mkdir(algorithm.ResultsDir+"/"+dir, 0o755); err != nil {
						t.Fatalf("error creating test directory: %s", err.Error())
					}
				}
			}
			for _, file := range tc.files {
				if _, err := os.Create(algorithm.ResultsDir + "/" + file); err != nil {
					t.Fatalf("error creating test file: %s", err.Error())
				}
			}

			if _, err := algorithm.ZipDirectory(); err != nil {
				t.Errorf("ZipDirectory() error = %v", err)
			}
		})
	}
}
