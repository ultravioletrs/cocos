// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMakeHandler(t *testing.T) {
	const (
		testServiceName = "test-service"
		testInstanceID  = "test-instance-123"
	)

	tests := []struct {
		name           string
		serviceName    string
		instanceID     string
		expectedRoutes int
	}{
		{
			name:           "valid handler creation",
			serviceName:    testServiceName,
			instanceID:     testInstanceID,
			expectedRoutes: 2, // /health and /metrics
		},
		{
			name:           "empty service name",
			serviceName:    "",
			instanceID:     testInstanceID,
			expectedRoutes: 2,
		},
		{
			name:           "empty instance ID",
			serviceName:    testServiceName,
			instanceID:     "",
			expectedRoutes: 2,
		},
		{
			name:           "both empty",
			serviceName:    "",
			instanceID:     "",
			expectedRoutes: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := chi.NewRouter()
			handler := MakeHandler(r, tt.serviceName, tt.instanceID)

			require.NotNil(t, handler)
			assert.Implements(t, (*http.Handler)(nil), handler)

			// Verify that the handler is actually the chi router
			assert.Equal(t, r, handler)
		})
	}
}

func TestHealthEndpoint(t *testing.T) {
	const (
		testServiceName = "test-service"
		testInstanceID  = "test-instance-123"
	)

	tests := []struct {
		name           string
		serviceName    string
		instanceID     string
		method         string
		path           string
		expectedStatus int
	}{
		{
			name:           "GET health endpoint success",
			serviceName:    testServiceName,
			instanceID:     testInstanceID,
			method:         http.MethodGet,
			path:           "/health",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "POST health endpoint not allowed",
			serviceName:    testServiceName,
			instanceID:     testInstanceID,
			method:         http.MethodPost,
			path:           "/health",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "PUT health endpoint not allowed",
			serviceName:    testServiceName,
			instanceID:     testInstanceID,
			method:         http.MethodPut,
			path:           "/health",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "DELETE health endpoint not allowed",
			serviceName:    testServiceName,
			instanceID:     testInstanceID,
			method:         http.MethodDelete,
			path:           "/health",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "health with empty service name",
			serviceName:    "",
			instanceID:     testInstanceID,
			method:         http.MethodGet,
			path:           "/health",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "health with empty instance ID",
			serviceName:    testServiceName,
			instanceID:     "",
			method:         http.MethodGet,
			path:           "/health",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := chi.NewRouter()
			handler := MakeHandler(r, tt.serviceName, tt.instanceID)

			req, err := http.NewRequest(tt.method, tt.path, nil)
			require.NoError(t, err)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedStatus == http.StatusOK {
				// Verify content type for successful health checks
				contentType := rr.Header().Get("Content-Type")
				assert.Contains(t, contentType, "application/health+json")

				// Verify response body contains service info
				body := rr.Body.String()
				if tt.serviceName != "" {
					assert.Contains(t, body, tt.serviceName)
				}
				if tt.instanceID != "" {
					assert.Contains(t, body, tt.instanceID)
				}
			}
		})
	}
}

func TestMetricsEndpoint(t *testing.T) {
	const (
		testServiceName = "test-service"
		testInstanceID  = "test-instance-123"
	)

	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
	}{
		{
			name:           "GET metrics endpoint success",
			method:         http.MethodGet,
			path:           "/metrics",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "POST metrics endpoint not allowed",
			method:         http.MethodPost,
			path:           "/metrics",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "PUT metrics endpoint not allowed",
			method:         http.MethodPut,
			path:           "/metrics",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "DELETE metrics endpoint not allowed",
			method:         http.MethodDelete,
			path:           "/metrics",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := chi.NewRouter()
			handler := MakeHandler(r, testServiceName, testInstanceID)

			req, err := http.NewRequest(tt.method, tt.path, nil)
			require.NoError(t, err)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedStatus == http.StatusOK {
				// Verify content type for Prometheus metrics
				contentType := rr.Header().Get("Content-Type")
				assert.Contains(t, contentType, "text/plain")

				// Verify response contains Prometheus metrics format
				body := rr.Body.String()
				assert.Contains(t, body, "# HELP")
				assert.Contains(t, body, "# TYPE")
			}
		})
	}
}

func TestNotFoundEndpoint(t *testing.T) {
	const (
		testServiceName = "test-service"
		testInstanceID  = "test-instance-123"
	)

	tests := []struct {
		name           string
		path           string
		expectedStatus int
	}{
		{
			name:           "root path not found",
			path:           "/",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "random path not found",
			path:           "/random-path",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "health typo not found",
			path:           "/helth",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "metrics typo not found",
			path:           "/metric",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "health with trailing slash",
			path:           "/health/",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "metrics with trailing slash",
			path:           "/metrics/",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := chi.NewRouter()
			handler := MakeHandler(r, testServiceName, testInstanceID)

			req, err := http.NewRequest(http.MethodGet, tt.path, nil)
			require.NoError(t, err)

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
		})
	}
}

func TestConcurrentRequests(t *testing.T) {
	const (
		testServiceName = "test-service"
		testInstanceID  = "test-instance-123"
		numRequests     = 100
	)

	r := chi.NewRouter()
	handler := MakeHandler(r, testServiceName, testInstanceID)

	// Test concurrent health requests
	t.Run("concurrent health requests", func(t *testing.T) {
		results := make(chan int, numRequests)

		for i := 0; i < numRequests; i++ {
			go func() {
				req, err := http.NewRequest(http.MethodGet, "/health", nil)
				require.NoError(t, err)

				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)

				results <- rr.Code
			}()
		}

		// Collect all results
		for i := 0; i < numRequests; i++ {
			status := <-results
			assert.Equal(t, http.StatusOK, status)
		}
	})

	// Test concurrent metrics requests
	t.Run("concurrent metrics requests", func(t *testing.T) {
		results := make(chan int, numRequests)

		for i := 0; i < numRequests; i++ {
			go func() {
				req, err := http.NewRequest(http.MethodGet, "/metrics", nil)
				require.NoError(t, err)

				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)

				results <- rr.Code
			}()
		}

		// Collect all results
		for i := 0; i < numRequests; i++ {
			status := <-results
			assert.Equal(t, http.StatusOK, status)
		}
	})
}

func TestHandlerWithCustomRouter(t *testing.T) {
	const (
		testServiceName = "test-service"
		testInstanceID  = "test-instance-123"
	)

	// Test with a router that already has some routes
	r := chi.NewRouter()
	r.Get("/existing", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("existing"))
	})

	handler := MakeHandler(r, testServiceName, testInstanceID)

	// Test that existing route still works
	req, err := http.NewRequest(http.MethodGet, "/existing", nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "existing", rr.Body.String())

	// Test that new routes work
	req, err = http.NewRequest(http.MethodGet, "/health", nil)
	require.NoError(t, err)

	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}
