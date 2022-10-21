package api

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

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
	nameKey      = "name"
	limitKey     = "limit"
	orderKey     = "order"
	dirKey       = "dir"
	metadataKey  = "metadata"
	sharedKey    = "shared"
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
		createDatasetsEndpoint(svc),
		decodeCreateDatasets,
		encodeResponse,
		opts...,
	))

	mux.Get("/datasets", kithttp.NewServer(
		listDatasetsEndpoint(svc),
		decodeList,
		encodeResponse,
		opts...,
	))

	mux.Get("/datasets/:id", kithttp.NewServer(
		viewDatasetsEndpoint(svc),
		decodeView,
		encodeResponse,
		opts...,
	))

	mux.Put("/datasets/:id", kithttp.NewServer(
		updateDatasetEndpoint(svc),
		decodeUpdateDataset,
		encodeResponse,
		opts...,
	))

	mux.Patch("/datasets/payload/:id", kithttp.NewServer(
		uploadDatasetEndpoint(svc),
		decodeUploadDataset,
		encodeResponse,
		opts...,
	))

	mux.Delete("/datasets/:id", kithttp.NewServer(
		removeDatasetEndpoint(svc),
		decodeView,
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

func decodeList(_ context.Context, r *http.Request) (interface{}, error) {
	o, err := apiutil.ReadUintQuery(r, offsetKey, defOffset)
	if err != nil {
		return nil, err
	}

	l, err := apiutil.ReadUintQuery(r, limitKey, defLimit)
	if err != nil {
		return nil, err
	}

	n, err := apiutil.ReadStringQuery(r, nameKey, "")
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
	shared, err := apiutil.ReadBoolQuery(r, sharedKey, false)
	if err != nil {
		return nil, err
	}

	req := listResourcesReq{
		pageMetadata: datasets.PageMetadata{
			Offset:              o,
			Limit:               l,
			Name:                n,
			Order:               or,
			Dir:                 d,
			Metadata:            m,
			FetchSharedDatasets: shared,
		},
	}

	return req, nil
}

func decodeView(_ context.Context, r *http.Request) (interface{}, error) {
	req := viewRequest{
		id: bone.GetValue(r, "id"),
	}
	return req, nil
}

func decodeUpdateDataset(_ context.Context, r *http.Request) (interface{}, error) {
	if !strings.Contains(r.Header.Get("Content-Type"), contentType) {
		return nil, errors.ErrUnsupportedContentType
	}

	req := updateReq{
		id: bone.GetValue(r, "id"),
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return nil, errors.Wrap(errors.ErrMalformedEntity, err)
	}

	return req, nil
}

func decodeUploadDataset(_ context.Context, r *http.Request) (interface{}, error) {
	if !strings.Contains(r.Header.Get("Content-Type"), contentType) {
		return nil, errors.ErrUnsupportedContentType
	}

	payload, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, errors.ErrMalformedEntity
	}
	defer r.Body.Close()

	req := uploadReq{
		token:   extractBearerToken(r),
		id:      bone.GetValue(r, "id"),
		Payload: payload,
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
