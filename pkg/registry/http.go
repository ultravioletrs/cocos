// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/absmach/supermq/pkg/errors"
)

var (
	// ErrDownloadFailed indicates a download operation failed.
	ErrDownloadFailed = errors.New("failed to download resource")
	// ErrInvalidURL indicates the provided URL is invalid.
	ErrInvalidURL = errors.New("invalid URL")
	// ErrMaxRetriesExceeded indicates maximum retry attempts were exceeded.
	ErrMaxRetriesExceeded = errors.New("maximum retry attempts exceeded")
)

// HTTPRegistry implements Registry for HTTP/HTTPS endpoints.
type HTTPRegistry struct {
	client  *http.Client
	config  Config
	logger  *slog.Logger
	headers map[string]string
}

// HTTPRegistryOption is a functional option for configuring HTTPRegistry.
type HTTPRegistryOption func(*HTTPRegistry)

// WithHeaders sets custom HTTP headers for requests.
func WithHeaders(headers map[string]string) HTTPRegistryOption {
	return func(r *HTTPRegistry) {
		r.headers = headers
	}
}

// WithLogger sets a custom logger for the HTTP registry.
func WithLogger(logger *slog.Logger) HTTPRegistryOption {
	return func(r *HTTPRegistry) {
		r.logger = logger
	}
}

// NewHTTPRegistry creates a new HTTP registry client.
func NewHTTPRegistry(config Config, opts ...HTTPRegistryOption) *HTTPRegistry {
	r := &HTTPRegistry{
		client: &http.Client{
			Timeout: config.Timeout,
		},
		config:  config,
		logger:  slog.Default(),
		headers: make(map[string]string),
	}

	for _, opt := range opts {
		opt(r)
	}

	return r
}

// Download retrieves a resource from an HTTP/HTTPS URL with retry logic.
func (r *HTTPRegistry) Download(ctx context.Context, url string) ([]byte, error) {
	if url == "" {
		return nil, ErrInvalidURL
	}

	var lastErr error
	retries := r.config.RetryCount
	if retries == 0 {
		retries = r.config.MaxRetries
	}
	if retries == 0 {
		retries = 3
	}

	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 1s, 2s, 4s, 8s...
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			r.logger.Info("retrying download", "attempt", attempt, "backoff", backoff, "url", url)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		data, err := r.downloadOnce(ctx, url)
		if err == nil {
			r.logger.Info("download successful", "url", url, "size", len(data))
			return data, nil
		}

		lastErr = err
		r.logger.Warn("download attempt failed", "attempt", attempt, "error", err, "url", url)
	}

	return nil, errors.Wrap(ErrMaxRetriesExceeded, lastErr)
}

// downloadOnce performs a single download attempt.
func (r *HTTPRegistry) downloadOnce(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Wrap(ErrDownloadFailed, err)
	}

	// Add custom headers
	for key, value := range r.headers {
		req.Header.Set(key, value)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(ErrDownloadFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Wrap(ErrDownloadFailed, fmt.Errorf("HTTP status %d", resp.StatusCode))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(ErrDownloadFailed, err)
	}

	return data, nil
}
