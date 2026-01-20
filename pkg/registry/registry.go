// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"time"
)

// Registry defines the interface for downloading resources from remote registries.
type Registry interface {
	// Download retrieves a resource from the specified URL.
	Download(ctx context.Context, url string) ([]byte, error)
}

// Config holds configuration for registry clients.
type Config struct {
	// Timeout specifies the maximum duration for a download operation.
	Timeout time.Duration
	// RetryCount specifies the number of retry attempts on failure.
	RetryCount int
	// MaxRetries specifies the maximum number of retries (deprecated, use RetryCount).
	MaxRetries int
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Timeout:    5 * time.Minute,
		RetryCount: 3,
		MaxRetries: 3,
	}
}
