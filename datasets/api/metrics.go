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

func (ms *metricsMiddleware) CreateDataset(ctx context.Context, dts datasets.Dataset) (id string, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "create_dataset").Add(1)
		ms.latency.With("method", "create_dataset").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.CreateDataset(ctx, dts)
}

func (ms *metricsMiddleware) ViewDataset(ctx context.Context, owner, id string) (datasets.Dataset, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "view_dataset").Add(1)
		ms.latency.With("method", "view_dataset").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.ViewDataset(ctx, owner, id)
}

func (ms *metricsMiddleware) ListDatasets(ctx context.Context, owner string, meta datasets.PageMetadata) (page datasets.Page, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "list_datasets").Add(1)
		ms.latency.With("method", "list_datasets").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.ListDatasets(ctx, owner, meta)
}

func (ms *metricsMiddleware) UpdateDataset(ctx context.Context, dataset datasets.Dataset) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "update_datasets").Add(1)
		ms.latency.With("method", "update_datasets").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.UpdateDataset(ctx, dataset)
}

func (ms *metricsMiddleware) UploadDataset(ctx context.Context, id, owner string, payload []byte) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "update_datasets").Add(1)
		ms.latency.With("method", "update_datasets").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.UploadDataset(ctx, id, owner, payload)
}

func (ms *metricsMiddleware) RemoveDataset(ctx context.Context, id string) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "remove_dataset").Add(1)
		ms.latency.With("method", "remove_dataset").Observe(time.Since(begin).Seconds())
	}(time.Now())
	return ms.svc.RemoveDataset(ctx, id)
}
