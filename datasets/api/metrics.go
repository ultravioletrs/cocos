package api

import (
	"context"
	"time"

	"github.com/go-kit/kit/metrics"
	"github.com/ultravioletrs/cocos/datasets"
)

var _ datasets.Service = (*metricsMiddleware)(nil)

type metricsMiddleware struct {
	counter metrics.Counter
	latency metrics.Histogram
	svc     datasets.Service
}

// MetricsMiddleware instruments core service by tracking request count and latency.
func MetricsMiddleware(svc datasets.Service, counter metrics.Counter, latency metrics.Histogram) datasets.Service {
	return &metricsMiddleware{
		counter: counter,
		latency: latency,
		svc:     svc,
	}
}

func (ms *metricsMiddleware) CreateDataset(ctx context.Context, token string, dataset datasets.Dataset) (string, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "create_dataset").Add(1)
		ms.latency.With("method", "create_dataset").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.CreateDataset(ctx, token, dataset)
}

func (ms *metricsMiddleware) ViewDataset(ctx context.Context, token, id string) (datasets.Dataset, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "view_dataset").Add(1)
		ms.latency.With("method", "view_dataset").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.ViewDataset(ctx, token, id)
}

func (ms *metricsMiddleware) ListDatasets(ctx context.Context, token string, meta datasets.PageMetadata) (page datasets.Page, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "list_datasets").Add(1)
		ms.latency.With("method", "list_datasets").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.ListDatasets(ctx, token, meta)
}

func (ms *metricsMiddleware) UpdateDataset(ctx context.Context, token string, dataset datasets.Dataset) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "update_datasets").Add(1)
		ms.latency.With("method", "update_datasets").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.UpdateDataset(ctx, token, dataset)
}

func (ms *metricsMiddleware) RemoveDataset(ctx context.Context, token, id string) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "remove_dataset").Add(1)
		ms.latency.With("method", "remove_dataset").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.RemoveDataset(ctx, token, id)
}
