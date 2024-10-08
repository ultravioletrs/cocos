// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/ultravioletrs/cocos/internal"
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
	cli := &CLI{}
	cmd := cli.NewFileHashCmd()

	content := []byte("test content")
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

	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)

	cmd.SetArgs([]string{tmpfile.Name()})
	err = cmd.Execute()
	if err != nil {
		t.Fatalf("Error executing command: %v", err)
	}

	expectedHash, err := internal.ChecksumHex(tmpfile.Name())
	if err != nil {
		t.Fatalf("Error computing expected hash: %v", err)
	}

	if !strings.Contains(output.String(), expectedHash) {
		t.Errorf("Expected output to contain hash %s, got %s", expectedHash, output.String())
	}
}

func TestNewFileHashCmdInvalidArgs(t *testing.T) {
	cli := &CLI{}
	cmd := cli.NewFileHashCmd()

	err := cmd.Execute()
	if err == nil {
		t.Error("Expected error when executing without arguments, got nil")
	}

	cmd.SetArgs([]string{"file1", "file2"})
	err = cmd.Execute()
	if err == nil {
		t.Error("Expected error when executing with too many arguments, got nil")
	}
}

func TestNewFileHashCmdNonExistentFile(t *testing.T) {
	cli := &CLI{}
	cmd := cli.NewFileHashCmd()

	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)

	cmd.SetArgs([]string{"non_existent_file.txt"})
	err := cmd.Execute()
	if err != nil {
		t.Fatalf("Error executing command: %v", err)
	}

	if !strings.Contains(output.String(), "Error computing hash") {
		t.Errorf("Expected output to contain 'Error computing hash', got %s", output.String())
	}
}
