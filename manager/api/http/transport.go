// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"net/http"

	"github.com/absmach/supermq"
	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MakeHandler returns a HTTP handler for API endpoints.
func MakeHandler(r *chi.Mux, svcName, instanceID string) http.Handler {
	r.Get("/health", supermq.Health(svcName, instanceID))
	r.Handle("/metrics", promhttp.Handler())

	return r
}
