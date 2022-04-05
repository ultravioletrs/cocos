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
	opentracing "github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/ultravioletrs/cocos/computations"
	httputil "github.com/ultravioletrs/cocos/internal/http"
)

const (
	contentType  = "application/json"
	offsetKey    = "offset"
	limitKey     = "limit"
	emailKey     = "email"
	metadataKey  = "metadata"
	defOffset    = 0
	defLimit     = 10
	bearerPrefix = "Bearer "
)

// MakeHandler returns a HTTP handler for API endpoints.
func MakeHandler(svc computations.Service, tracer opentracing.Tracer, logger logger.Logger) http.Handler {
	opts := []kithttp.ServerOption{
		// kithttp.ServerErrorEncoder(apiutil.LoggingErrorEncoder(logger, encodeError)),
	}

	mux := bone.New()

	mux.Post("/computations", kithttp.NewServer(
		kitot.TraceServer(tracer, "register")(createComputation(svc)),
		decodeCreateComputation,
		encodeResponse,
		opts...,
	))

	mux.GetFunc("/health", httputil.Health("computations", "Computation management service"))
	mux.Handle("/metrics", promhttp.Handler())

	return mux
}

func decodeCreateComputation(_ context.Context, r *http.Request) (interface{}, error) {
	req := createReq{
		token: extractBearerToken(r),
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
