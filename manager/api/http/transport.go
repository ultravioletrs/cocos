// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

package http

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/go-zoo/bone"
	"github.com/mainflux/mainflux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/ultravioletrs/manager/manager"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

const contentType = "application/json"

var (
	errUnsupportedContentType = errors.New("unsupported content type")
	errInvalidQueryParams     = errors.New("invalid query params")
)

// MakeHandler returns a HTTP handler for API endpoints.
func MakeHandler(svc manager.Service, instanceID string) http.Handler {
	opts := []kithttp.ServerOption{
		kithttp.ServerErrorEncoder(encodeError),
	}

	r := bone.New()

	r.Post("/domain", otelhttp.NewHandler(kithttp.NewServer(
		createLibvirtDomainEndpoint(svc),
		decodeCreateLibvirtDomain,
		encodeResponse,
		opts...,
	), "create_domain"))

	r.Get("/qemu", otelhttp.NewHandler(kithttp.NewServer(
		createQemuVMEndpoint(svc),
		decodeCreateQemuVMRequest,
		encodeResponse,
		opts...,
	), "create_qemu_vm"))

	r.Post("/run", otelhttp.NewHandler(kithttp.NewServer(
		runEndpoint(svc),
		decodeRun,
		encodeResponse,
		opts...,
	), "run"))

	r.GetFunc("/health", mainflux.Health("manager", instanceID))
	r.Handle("/metrics", promhttp.Handler())

	return r
}

func decodeCreateLibvirtDomain(_ context.Context, r *http.Request) (interface{}, error) {
	if !strings.Contains(r.Header.Get("Content-Type"), contentType) {
		return nil, errUnsupportedContentType
	}

	req := createLibvirtDomainReq{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, err
	}

	return req, nil
}

func decodeCreateQemuVMRequest(_ context.Context, r *http.Request) (interface{}, error) {
	return createQemuVMReq{}, nil
}

func decodeRun(_ context.Context, r *http.Request) (interface{}, error) {
	if !strings.Contains(r.Header.Get("Content-Type"), contentType) {
		return nil, errUnsupportedContentType
	}

	var req runReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, err
	}

	return req, nil
}

func encodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	w.Header().Set("Content-Type", contentType)

	if ar, ok := response.(mainflux.Response); ok {
		for k, v := range ar.Headers() {
			w.Header().Set(k, v)
		}

		w.WriteHeader(ar.Code())

		if ar.Empty() {
			return nil
		}
	}

	return json.NewEncoder(w).Encode(response)
}

func encodeError(_ context.Context, err error, w http.ResponseWriter) {
	w.Header().Set("Content-Type", contentType)

	switch err {
	case manager.ErrMalformedEntity:
		w.WriteHeader(http.StatusBadRequest)
	case manager.ErrNotFound:
		w.WriteHeader(http.StatusNotFound)
	case manager.ErrUnauthorizedAccess:
		w.WriteHeader(http.StatusForbidden)
	case errUnsupportedContentType:
		w.WriteHeader(http.StatusUnsupportedMediaType)
	case errInvalidQueryParams:
		w.WriteHeader(http.StatusBadRequest)
	case io.ErrUnexpectedEOF:
		w.WriteHeader(http.StatusBadRequest)
	case io.EOF:
		w.WriteHeader(http.StatusBadRequest)
	default:
		switch err.(type) {
		case *json.SyntaxError:
			w.WriteHeader(http.StatusBadRequest)
		case *json.UnmarshalTypeError:
			w.WriteHeader(http.StatusBadRequest)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}
