// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build !test
// +build !test

package api

import (
	"context"
	"time"

	"github.com/go-kit/kit/metrics"
	"github.com/ultravioletrs/cocos/manager"
)

var _ manager.Service = (*metricsMiddleware)(nil)

type metricsMiddleware struct {
	counter metrics.Counter
	latency metrics.Histogram
	svc     manager.Service
}

// MetricsMiddleware instruments core service by tracking request count and
// latency.
func MetricsMiddleware(svc manager.Service, counter metrics.Counter, latency metrics.Histogram) manager.Service {
	return &metricsMiddleware{
		counter: counter,
		latency: latency,
		svc:     svc,
	}
}

func (ms *metricsMiddleware) CreateVM(ctx context.Context, req *manager.CreateReq) (string, string, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "Run").Add(1)
		ms.latency.With("method", "Run").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.CreateVM(ctx, req)
}

func (ms *metricsMiddleware) RemoveVM(ctx context.Context, computationID string) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "Stop").Add(1)
		ms.latency.With("method", "Stop").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.RemoveVM(ctx, computationID)
}

func (ms *metricsMiddleware) FetchAttestationPolicy(ctx context.Context, cmpId string) ([]byte, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "FetchAttestationPolicy").Add(1)
		ms.latency.With("method", "FetchAttestationPolicy").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.FetchAttestationPolicy(ctx, cmpId)
}

func (ms *metricsMiddleware) ReturnCVMInfo(ctx context.Context) (string, int, string, string) {
	defer func(begin time.Time) {
		ms.counter.With("method", "ReturnCVMInfo").Add(1)
		ms.latency.With("method", "ReturnCVMInfo").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.ReturnCVMInfo(ctx)
}

func (ms *metricsMiddleware) Shutdown() error {
	defer func(begin time.Time) {
		ms.counter.With("method", "Shutdown").Add(1)
		ms.latency.With("method", "Shutdown").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Shutdown()
}
