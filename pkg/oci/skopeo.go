// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	// OCICryptKeyproviderConfig is the environment variable for ocicrypt config
	OCICryptKeyproviderConfig = "OCICRYPT_KEYPROVIDER_CONFIG"

	// DefaultOCICryptConfig is the default path to ocicrypt config
	DefaultOCICryptConfig = "/etc/ocicrypt_keyprovider.conf"

	// DecryptionKeyProvider is the decryption key provider for CoCo
	DecryptionKeyProvider = "provider:attestation-agent:cc_kbc::null"
)

// SkopeoClient wraps skopeo command-line operations
type SkopeoClient struct {
	skopeoPath string
	workDir    string
}

// NewSkopeoClient creates a new Skopeo client
func NewSkopeoClient(workDir string) (*SkopeoClient, error) {
	// Find skopeo binary
	skopeoPath, err := exec.LookPath("skopeo")
	if err != nil {
		return nil, fmt.Errorf("skopeo not found in PATH: %w", err)
	}

	// Ensure work directory exists
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create work directory: %w", err)
	}

	return &SkopeoClient{
		skopeoPath: skopeoPath,
		workDir:    workDir,
	}, nil
}

// PullAndDecrypt pulls an OCI image and decrypts it if encrypted
func (s *SkopeoClient) PullAndDecrypt(ctx context.Context, source ResourceSource, destDir string) error {
	// Ensure destination directory exists
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	args := []string{"copy"}

	// Add decryption key if image is encrypted
	if source.Encrypted {
		args = append(args, "--decryption-key", DecryptionKeyProvider)
	}

	// Add insecure policy for testing (TODO: use proper policy in production)
	args = append(args, "--insecure-policy")

	// Source and destination
	args = append(args, source.URI, "oci:"+destDir)

	cmd := exec.CommandContext(ctx, s.skopeoPath, args...)

	// Set OCICRYPT environment
	cmd.Env = append(os.Environ(),
		OCICryptKeyproviderConfig+"="+DefaultOCICryptConfig)

	// Set working directory
	cmd.Dir = s.workDir

	// Capture output
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("skopeo copy failed: %w\nOutput: %s", err, string(output))
	}

	return nil
}

// Inspect inspects an OCI image and returns basic manifest information
func (s *SkopeoClient) Inspect(ctx context.Context, imageRef string) (*ImageManifest, error) {
	args := []string{"inspect", "--insecure-policy", imageRef}

	cmd := exec.CommandContext(ctx, s.skopeoPath, args...)
	cmd.Env = append(os.Environ(),
		OCICryptKeyproviderConfig+"="+DefaultOCICryptConfig)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("skopeo inspect failed: %w\nOutput: %s", err, string(output))
	}

	// For now, return basic info
	// TODO: Parse JSON output for detailed manifest info
	return &ImageManifest{
		Reference: imageRef,
	}, nil
}

// GetLocalImagePath returns the path to a local OCI image directory
func (s *SkopeoClient) GetLocalImagePath(name string) string {
	return filepath.Join(s.workDir, name)
}
