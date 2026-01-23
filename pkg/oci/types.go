// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package oci

// ResourceType defines the type of OCI resource
type ResourceType string

const (
	// ResourceTypeOCIImage represents a standard OCI image
	ResourceTypeOCIImage ResourceType = "oci-image"
)

// ResourceSource defines the source of an OCI resource
type ResourceSource struct {
	// Type of resource (oci-image)
	Type ResourceType `json:"type"`

	// URI is the OCI image reference (e.g., "docker://registry/repo:tag")
	URI string `json:"uri"`

	// Encrypted indicates if the image is encrypted
	Encrypted bool `json:"encrypted"`

	// KBSResourcePath is the KBS resource path for the decryption key
	// (e.g., "default/key/algo-key")
	KBSResourcePath string `json:"kbs_resource_path,omitempty"`
}

// ImageManifest represents basic OCI image manifest information
type ImageManifest struct {
	// Reference is the original image reference
	Reference string

	// Digest is the image digest
	Digest string

	// Layers are the layer digests
	Layers []string
}
