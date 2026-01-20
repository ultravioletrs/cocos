// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/absmach/supermq/pkg/errors"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

var (
	// ErrInvalidS3URL indicates the S3 URL format is invalid.
	ErrInvalidS3URL = errors.New("invalid S3 URL format")
	// ErrS3DownloadFailed indicates an S3 download operation failed.
	ErrS3DownloadFailed = errors.New("failed to download from S3")
)

// S3Registry implements Registry for AWS S3 and S3-compatible endpoints.
type S3Registry struct {
	client *s3.Client
	config Config
	logger *slog.Logger
}

// S3Config holds S3-specific configuration.
type S3Config struct {
	// Region is the AWS region (e.g., "us-east-1").
	Region string
	// Endpoint is the S3 endpoint URL (for S3-compatible services like MinIO).
	Endpoint string
	// AccessKeyID is the AWS access key ID.
	AccessKeyID string
	// SecretAccessKey is the AWS secret access key.
	SecretAccessKey string
	// UsePathStyle forces path-style addressing (required for MinIO).
	UsePathStyle bool
}

// S3RegistryOption is a functional option for configuring S3Registry.
type S3RegistryOption func(*S3Registry)

// WithS3Logger sets a custom logger for the S3 registry.
func WithS3Logger(logger *slog.Logger) S3RegistryOption {
	return func(r *S3Registry) {
		r.logger = logger
	}
}

// NewS3Registry creates a new S3 registry client.
func NewS3Registry(ctx context.Context, config Config, s3cfg S3Config, opts ...S3RegistryOption) (*S3Registry, error) {
	r := &S3Registry{
		config: config,
		logger: slog.Default(),
	}

	for _, opt := range opts {
		opt(r)
	}

	// Build AWS config
	var awsCfgOpts []func(*awsconfig.LoadOptions) error

	if s3cfg.Region != "" {
		awsCfgOpts = append(awsCfgOpts, awsconfig.WithRegion(s3cfg.Region))
	}

	// Use static credentials if provided
	if s3cfg.AccessKeyID != "" && s3cfg.SecretAccessKey != "" {
		awsCfgOpts = append(awsCfgOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(s3cfg.AccessKeyID, s3cfg.SecretAccessKey, ""),
		))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsCfgOpts...)
	if err != nil {
		return nil, errors.Wrap(ErrS3DownloadFailed, err)
	}

	// Build S3 client options
	s3Opts := []func(*s3.Options){
		func(o *s3.Options) {
			o.UsePathStyle = s3cfg.UsePathStyle
		},
	}

	if s3cfg.Endpoint != "" {
		s3Opts = append(s3Opts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(s3cfg.Endpoint)
		})
	}

	r.client = s3.NewFromConfig(awsCfg, s3Opts...)

	return r, nil
}

// Download retrieves a resource from S3 with retry logic.
func (r *S3Registry) Download(ctx context.Context, s3URL string) ([]byte, error) {
	bucket, key, err := parseS3URL(s3URL)
	if err != nil {
		return nil, err
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
			r.logger.Info("retrying S3 download", "attempt", attempt, "backoff", backoff, "bucket", bucket, "key", key)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		data, err := r.downloadOnce(ctx, bucket, key)
		if err == nil {
			r.logger.Info("S3 download successful", "bucket", bucket, "key", key, "size", len(data))
			return data, nil
		}

		lastErr = err
		r.logger.Warn("S3 download attempt failed", "attempt", attempt, "error", err, "bucket", bucket, "key", key)
	}

	return nil, errors.Wrap(ErrMaxRetriesExceeded, lastErr)
}

// downloadOnce performs a single S3 download attempt.
func (r *S3Registry) downloadOnce(ctx context.Context, bucket, key string) ([]byte, error) {
	// Add timeout to context
	downloadCtx, cancel := context.WithTimeout(ctx, r.config.Timeout)
	defer cancel()

	result, err := r.client.GetObject(downloadCtx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, errors.Wrap(ErrS3DownloadFailed, err)
	}
	defer result.Body.Close()

	data, err := io.ReadAll(result.Body)
	if err != nil {
		return nil, errors.Wrap(ErrS3DownloadFailed, err)
	}

	return data, nil
}

// parseS3URL parses an S3 URL and extracts bucket and key.
// Supports formats: s3://bucket/key and https://bucket.s3.region.amazonaws.com/key
func parseS3URL(s3URL string) (bucket, key string, err error) {
	if s3URL == "" {
		return "", "", ErrInvalidS3URL
	}

	// Handle s3:// scheme
	if strings.HasPrefix(s3URL, "s3://") {
		s3URL = strings.TrimPrefix(s3URL, "s3://")
		parts := strings.SplitN(s3URL, "/", 2)
		if len(parts) != 2 {
			return "", "", errors.Wrap(ErrInvalidS3URL, fmt.Errorf("expected format s3://bucket/key"))
		}
		return parts[0], parts[1], nil
	}

	// Handle https:// scheme
	if strings.HasPrefix(s3URL, "https://") || strings.HasPrefix(s3URL, "http://") {
		u, err := url.Parse(s3URL)
		if err != nil {
			return "", "", errors.Wrap(ErrInvalidS3URL, err)
		}

		// Extract bucket from hostname (bucket.s3.region.amazonaws.com or s3.region.amazonaws.com/bucket)
		host := u.Hostname()
		path := strings.TrimPrefix(u.Path, "/")

		// Virtual-hosted-style: bucket.s3.region.amazonaws.com/key
		if strings.Contains(host, ".s3.") || strings.Contains(host, ".s3-") {
			parts := strings.SplitN(host, ".", 2)
			return parts[0], path, nil
		}

		// Path-style: s3.region.amazonaws.com/bucket/key or endpoint/bucket/key
		parts := strings.SplitN(path, "/", 2)
		if len(parts) != 2 {
			return "", "", errors.Wrap(ErrInvalidS3URL, fmt.Errorf("expected path format /bucket/key"))
		}
		return parts[0], parts[1], nil
	}

	return "", "", errors.Wrap(ErrInvalidS3URL, fmt.Errorf("unsupported URL scheme"))
}
