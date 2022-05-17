//go:build !test

package api

import (
	"context"
	"time"

	"github.com/go-kit/kit/metrics"
	"github.com/ultravioletrs/cocos/computations"
)

var _ computations.Service = (*metricsMiddleware)(nil)

type metricsMiddleware struct {
	counter metrics.Counter
	latency metrics.Histogram
	svc     computations.Service
}

// MetricsMiddleware instruments core service by tracking request count and latency.
func MetricsMiddleware(svc computations.Service, counter metrics.Counter, latency metrics.Histogram) computations.Service {
	return &metricsMiddleware{
		counter: counter,
		latency: latency,
		svc:     svc,
	}
}

func (ms *metricsMiddleware) CreateComputation(ctx context.Context, token string, computation computations.Computation) (string, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "create_computation").Add(1)
		ms.latency.With("method", "create_computation").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.CreateComputation(ctx, token, computation)
}

func (ms *metricsMiddleware) ViewComputation(ctx context.Context, token, id string) (computations.Computation, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "view_computation").Add(1)
		ms.latency.With("method", "view_computation").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.ViewComputation(ctx, token, id)
}

func (ms *metricsMiddleware) ListComputations(ctx context.Context, token string, meta computations.PageMetadata) (page computations.Page, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "list_computations").Add(1)
		ms.latency.With("method", "list_computations").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.ListComputations(ctx, token, meta)
}

func (ms *metricsMiddleware) UpdateComputation(ctx context.Context, token string, computation computations.Computation) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "update_computations").Add(1)
		ms.latency.With("method", "update_computations").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.UpdateComputation(ctx, token, computation)
}

func (ms *metricsMiddleware) RemoveComputation(ctx context.Context, token, id string) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "remove_computation").Add(1)
		ms.latency.With("method", "remove_computation").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.RemoveComputation(ctx, token, id)
}
