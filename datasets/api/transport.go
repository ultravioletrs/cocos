package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	kitot "github.com/go-kit/kit/tracing/opentracing"
	kithttp "github.com/go-kit/kit/transport/http"
	"github.com/go-zoo/bone"
	"github.com/mainflux/mainflux"
	"github.com/mainflux/mainflux/logger"
	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/ultravioletrs/cocos/datasets"
	"github.com/ultravioletrs/cocos/internal/apiutil"
	httputil "github.com/ultravioletrs/cocos/internal/http"
)

const (
	contentType  = "application/json"
	offsetKey    = "offset"
	limitKey     = "limit"
	orderKey     = "order"
	dirKey       = "dir"
	metadataKey  = "metadata"
	defOffset    = 0
	defLimit     = 10
	bearerPrefix = "Bearer "
)

// MakeHandler returns a HTTP handler for API endpoints.
func MakeHandler(svc datasets.Service, tracer opentracing.Tracer, logger logger.Logger) http.Handler {
	opts := []kithttp.ServerOption{
		kithttp.ServerErrorEncoder(apiutil.LoggingErrorEncoder(logger, encodeError)),
	}

	mux := bone.New()

	mux.Post("/datasets", kithttp.NewServer(
		kitot.TraceServer(tracer, "create_datasets")(createDatasetsEndpoint(svc)),
		decodeCreateDatasets,
		encodeResponse,
		opts...,
	))

	mux.Get("/datasets", kithttp.NewServer(
		kitot.TraceServer(tracer, "list_datasets")(listDatasetsEndpoint(svc)),
		listDatasetsDataset,
		encodeResponse,
		opts...,
	))

	mux.Get("/datasets/:id", kithttp.NewServer(
		kitot.TraceServer(tracer, "list_datasets")(viewDatasetsEndpoint(svc)),
		viewDatasetsDataset,
		encodeResponse,
		opts...,
	))

	mux.Put("/datasets/:id", kithttp.NewServer(
		kitot.TraceServer(tracer, "list_datasets")(updateDatasetsEndpoint(svc)),
		updateDatasetsDataset,
		encodeResponse,
		opts...,
	))

	mux.Delete("/datasets/:id", kithttp.NewServer(
		kitot.TraceServer(tracer, "list_datasets")(removeDatasetsEndpoint(svc)),
		viewDatasetsDataset,
		encodeResponse,
		opts...,
	))

	mux.GetFunc("/health", httputil.Health("datasets", "Datasets management service"))
	mux.Handle("/metrics", promhttp.Handler())

	return mux
}

func decodeCreateDatasets(_ context.Context, r *http.Request) (interface{}, error) {
	req := createReq{
		token: extractBearerToken(r),
	}
	if err := json.NewDecoder(r.Body).Decode(&req.dataset); err != nil {
		return nil, errors.Wrap(errors.ErrMalformedEntity, err)
	}

	return req, nil
}

func listDatasetsDataset(_ context.Context, r *http.Request) (interface{}, error) {
	o, err := apiutil.ReadUintQuery(r, offsetKey, defOffset)
	if err != nil {
		return nil, err
	}

	l, err := apiutil.ReadUintQuery(r, limitKey, defLimit)
	if err != nil {
		return nil, err
	}

	or, err := apiutil.ReadStringQuery(r, orderKey, "")
	if err != nil {
		return nil, err
	}

	d, err := apiutil.ReadStringQuery(r, dirKey, "")
	if err != nil {
		return nil, err
	}

	m, err := apiutil.ReadMetadataQuery(r, metadataKey, nil)
	if err != nil {
		return nil, err
	}
	req := listReq{

		token: extractBearerToken(r),
		meta: datasets.PageMetadata{
			Offset:   o,
			Limit:    l,
			Order:    or,
			Dir:      d,
			Metadata: m,
		},
	}

	return req, nil
}

func viewDatasetsDataset(_ context.Context, r *http.Request) (interface{}, error) {
	req := viewReq{
		token: extractBearerToken(r),
		id:    bone.GetValue(r, "id"),
	}
	return req, nil
}

func updateDatasetsDataset(_ context.Context, r *http.Request) (interface{}, error) {
	if !strings.Contains(r.Header.Get("Content-Type"), contentType) {
		return nil, errors.ErrUnsupportedContentType
	}

	req := updateReq{
		token: extractBearerToken(r),
		id:    bone.GetValue(r, "id"),
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(errors.ErrMalformedEntity, err)
	}

	return req, nil
}

func encodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	if ar, ok := response.(mainflux.Response); ok {
		for k, v := range ar.Headers() {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(ar.Code())

		if ar.Empty() {
			return nil
		}
	}
	return json.NewEncoder(w).Encode(response)
}

func encodeError(_ context.Context, err error, w http.ResponseWriter) {
	switch {
	case errors.Contains(err, errors.ErrInvalidQueryParams),
		errors.Contains(err, errors.ErrMalformedEntity):
		w.WriteHeader(http.StatusBadRequest)
	case errors.Contains(err, errors.ErrCreateEntity),
		errors.Contains(err, errors.ErrUpdateEntity),
		errors.Contains(err, errors.ErrViewEntity),
		errors.Contains(err, errors.ErrRemoveEntity):
		w.WriteHeader(http.StatusInternalServerError)
	default:
		w.WriteHeader(http.StatusInternalServerError)
	}
	if errorVal, ok := err.(errors.Error); ok {
		w.Header().Set("Content-Type", contentType)
		if err := json.NewEncoder(w).Encode(errorRes{Err: errorVal.Msg()}); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}

func extractBearerToken(r *http.Request) string {
	token := r.Header.Get("Authorization")
	if !strings.HasPrefix(token, bearerPrefix) {
		return ""
	}
	return strings.TrimPrefix(token, bearerPrefix)
}
