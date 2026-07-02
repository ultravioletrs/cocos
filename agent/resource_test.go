// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/ultravioletrs/cocos/pkg/resource"
)

type MockDownloader struct {
	mock.Mock
}

func (m *MockDownloader) Download(ctx context.Context, url string, destPath string) error {
	args := m.Called(ctx, url, destPath)
	if args.Error(0) == nil {
		// Simulate writing to destPath if it's a success
		content := "mock content"
		if len(args) > 1 {
			if c, ok := args.Get(1).(string); ok {
				content = c
			}
		}
		_ = os.MkdirAll(filepath.Dir(destPath), 0o755)
		_ = os.WriteFile(destPath, []byte(content), 0o644)
	}
	return args.Error(0)
}

func (m *MockDownloader) Type() string {
	return m.Called().String(0)
}

func TestDownloadAndDecryptGenericResource(t *testing.T) {
	registry := resource.NewRegistry()
	mockDownloader := new(MockDownloader)
	mockDownloader.On("Type").Return(resource.SourceTypeHTTP)
	registry.Register(mockDownloader)

	attestationClient := new(MockAttestationClient)
	attestationClient.On("GetKbsToken", mock.Anything).Return([]byte("mockToken"), nil).Maybe()

	svc := &agentService{
		logger:            slog.Default(),
		resourceRegistry:  registry,
		attestationClient: attestationClient,
		computation: Computation{
			Algorithm: &Algorithm{
				KBS: &KBSConfig{
					Enabled: true,
					URL:     "http://mock-kbs",
				},
			},
		},
	}

	ctx := context.Background()

	t.Run("Successful download without encryption", func(t *testing.T) {
		source := &ResourceSource{
			URL: "http://example.com/resource",
		}
		destPath := filepath.Join(os.TempDir(), "cocos-resources", "algo", "resource")
		mockDownloader.On("Download", ctx, source.URL, destPath).Return(nil, "some data").Once()

		res, err := svc.downloadAndDecryptGenericResource(ctx, source, resource.SourceTypeHTTP, "", "algo")
		assert.NoError(t, err)
		assert.Equal(t, []byte("some data"), res.Data)
		mockDownloader.AssertExpectations(t)
	})

	t.Run("Successful download with encryption", func(t *testing.T) {
		key := make([]byte, 32)
		_, _ = io.ReadFull(rand.Reader, key)

		plaintext := []byte("secret data")
		block, _ := aes.NewCipher(key)
		gcm, _ := cipher.NewGCM(block)
		nonce := make([]byte, gcm.NonceSize())
		_, _ = io.ReadFull(rand.Reader, nonce)
		ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

		// Mock KBS
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(key)
		}))
		defer ts.Close()

		svc.computation.Algorithm.KBS.URL = ts.URL

		source := &ResourceSource{
			URL:             "http://example.com/encrypted",
			Encrypted:       true,
			KBSResourcePath: "keys/1",
		}
		destPath := filepath.Join(os.TempDir(), "cocos-resources", "data", "encrypted")
		mockDownloader.On("Download", ctx, source.URL, destPath).Return(nil, string(ciphertext)).Once()

		res, err := svc.downloadAndDecryptGenericResource(ctx, source, resource.SourceTypeHTTP, svc.computation.Algorithm.KBS.URL, "data")
		assert.NoError(t, err)
		assert.Equal(t, plaintext, res.Data)
		mockDownloader.AssertExpectations(t)
	})

	t.Run("Registry not initialized", func(t *testing.T) {
		badSvc := &agentService{logger: slog.Default()}
		_, err := badSvc.downloadAndDecryptGenericResource(ctx, &ResourceSource{}, "http", "", "algo")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "resource registry not initialized")
	})
}

func TestGetKeyFromKBS(t *testing.T) {
	attestationClient := new(MockAttestationClient)
	attestationClient.On("GetKbsToken", mock.Anything).Return([]byte("mockToken"), nil).Maybe()

	svc := &agentService{
		logger:            slog.Default(),
		attestationClient: attestationClient,
		computation: Computation{
			Algorithm: &Algorithm{
				KBS: &KBSConfig{
					Enabled: true,
				},
			},
		},
	}
	ctx := context.Background()

	t.Run("KBS disabled", func(t *testing.T) {
		svc.computation.Algorithm.KBS.Enabled = false
		_, err := svc.getKeyFromKBS(ctx, "", "path")
		assert.Error(t, err)
	})

	t.Run("Successful fetch", func(t *testing.T) {
		svc.computation.Algorithm.KBS.Enabled = true
		key := []byte("this is a 32-byte key!!!!!!!!!!!")
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Contains(t, r.URL.Path, "resource/path")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(key)
		}))
		defer ts.Close()
		svc.computation.Algorithm.KBS.URL = ts.URL

		fetched, err := svc.getKeyFromKBS(ctx, svc.computation.Algorithm.KBS.URL, "path")
		assert.NoError(t, err)
		assert.Equal(t, key, fetched)
	})

	t.Run("KBS error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()
		svc.computation.Algorithm.KBS.URL = ts.URL

		_, err := svc.getKeyFromKBS(ctx, svc.computation.Algorithm.KBS.URL, "path")
		assert.Error(t, err)
	})
}

func TestInferSourceTypeDetailed(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{"s3://bucket/key", resource.SourceTypeS3},
		{"gs://bucket/key", resource.SourceTypeGCS},
		{"https://example.com/file", resource.SourceTypeHTTPS},
		{"http://example.com/file", resource.SourceTypeHTTP},
		{"docker://ubuntu", resource.SourceTypeOCIImage},
		{"oci:/path/to/dir", resource.SourceTypeOCIImage},
		{"ubuntu:latest", resource.SourceTypeOCIImage},
		{"myregistry.io/myimage:tag", resource.SourceTypeOCIImage},
		{"invalid-url-no-slash", ""},
		{"", ""},
		{"ftp://server/file", ""},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, inferSourceType(tt.url), "URL: %s", tt.url)
	}
}
