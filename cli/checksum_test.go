// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewFileHashCmd(t *testing.T) {
	cli := &CLI{}
	cmd := cli.NewFileHashCmd()

	if cmd.Use != "checksum" {
		t.Errorf("Expected Use to be 'checksum', got %s", cmd.Use)
	}

	if cmd.Short != "Compute the sha3-256 hash of a file" {
		t.Errorf("Expected Short to be 'Compute the sha3-256 hash of a file', got %s", cmd.Short)
	}

	if cmd.Example != "checksum <file>" {
		t.Errorf("Expected Example to be 'checksum <file>', got %s", cmd.Example)
	}
}

func TestNewFileHashCmdRun(t *testing.T) {
	testCases := []struct {
		name        string
		isManifest  bool
		toBase64    bool
		expectedOut string
		expectedErr string
	}{
		{
			name:        "Valid file",
			isManifest:  false,
			toBase64:    false,
			expectedOut: "Hash of file:",
			expectedErr: "",
		},
		{
			name:        "Valid manifest file",
			isManifest:  true,
			toBase64:    false,
			expectedOut: "Hash of manifest file:",
			expectedErr: "",
		},
		{
			name:        "Valid file with base64 output",
			isManifest:  false,
			toBase64:    true,
			expectedOut: "Hash of file:",
			expectedErr: "",
		},
		{
			name:        "Non-existent file",
			isManifest:  false,
			toBase64:    false,
			expectedOut: "Error computing hash:",
			expectedErr: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cli := &CLI{}
			cmd := cli.NewFileHashCmd()

			var output bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetErr(&output)

			err := cmd.Flags().Set("manifest", fmt.Sprint(tc.isManifest))
			assert.Nil(t, err)
			err = cmd.Flags().Set("base64", fmt.Sprint(tc.toBase64))
			assert.Nil(t, err)

			if tc.name == "Non-existent file" {
				cmd.SetArgs([]string{"non_existent_file.txt"})
			} else {
				content := []byte("{}")
				tmpfile, err := os.CreateTemp("", "example")
				if err != nil {
					t.Fatal(err)
				}
				defer os.Remove(tmpfile.Name())

				if _, err := tmpfile.Write(content); err != nil {
					t.Fatal(err)
				}
				if err := tmpfile.Close(); err != nil {
					t.Fatal(err)
				}

				cmd.SetArgs([]string{tmpfile.Name()})
			}

			err = cmd.Execute()
			if err != nil {
				t.Fatalf("Error executing command: %v", err)
			}

			out := output.String()
			if !strings.Contains(out, tc.expectedOut) {
				t.Errorf("Expected output to contain '%s', got '%s'", tc.expectedOut, out)
			}

			if tc.expectedErr != "" && !strings.Contains(out, tc.expectedErr) {
				t.Errorf("Expected output to contain '%s', got '%s'", tc.expectedErr, out)
			}
		})
	}
}

func TestManifestChecksum(t *testing.T) {
	testCases := []struct {
		name        string
		jsonContent string
		expectedSum string
	}{
		{
			name: "Valid manifest file",
			jsonContent: `{
				"id": "1234",
				"name": "Example Computation",
				"description": "This is an example computation"
			}`,
			expectedSum: "a99683e4d22ba54cefa51aa49fb2e97a92b828c088395992ddff16a6236f3299",
		},
		{
			name:        "Invalid JSON",
			jsonContent: `{`,
			expectedSum: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := os.CreateTemp("", "test")
			assert.Nil(t, err)

			t.Cleanup(func() {
				os.Remove(f.Name())
			})

			_, err = f.WriteString(tc.jsonContent)
			assert.NoError(t, err)

			err = f.Close()
			assert.Nil(t, err)

			hash, err := manifestChecksum(f.Name())
			if tc.expectedSum == "" && err == nil {
				t.Errorf("Expected error, got nil")
			}
			if tc.expectedSum != "" && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if hash != tc.expectedSum {
				t.Errorf("Expected hash %s, got %s", tc.expectedSum, hash)
			}
		})
	}
}

func TestHexToBase64(t *testing.T) {
	testCases := []struct {
		name        string
		hexInput    string
		expectedOut string
	}{
		{
			name:        "Valid hex input",
			hexInput:    "48656c6c6f",
			expectedOut: "SGVsbG8=",
		},
		{
			name:        "Invalid hex input",
			hexInput:    "invalid-hex",
			expectedOut: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			out := hexToBase64(tc.hexInput)
			if out != tc.expectedOut {
				t.Errorf("Expected %s, got %s", tc.expectedOut, out)
			}
		})
	}
}

func TestHashOut(t *testing.T) {
	testCases := []struct {
		name        string
		hashHex     string
		toBase64    bool
		expectedOut string
	}{
		{
			name:        "Hex output",
			hashHex:     "48656c6c6f",
			toBase64:    false,
			expectedOut: "48656c6c6f",
		},
		{
			name:        "Base64 output",
			hashHex:     "48656c6c6f",
			toBase64:    true,
			expectedOut: "SGVsbG8=",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			toBase64 = tc.toBase64
			out := hashOut(tc.hashHex)
			if out != tc.expectedOut {
				t.Errorf("Expected %s, got %s", tc.expectedOut, out)
			}
		})
	}
}
