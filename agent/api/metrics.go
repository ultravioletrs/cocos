// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build !test
// +build !test

package api

import (
	"context"
	"time"

	"github.com/go-kit/kit/metrics"
	"github.com/ultravioletrs/cocos/agent"
)

var _ agent.Service = (*metricsMiddleware)(nil)

type metricsMiddleware struct {
	counter metrics.Counter
	latency metrics.Histogram
	svc     agent.Service
}

// MetricsMiddleware instruments core service by tracking request count and
// latency.
func MetricsMiddleware(svc agent.Service, counter metrics.Counter, latency metrics.Histogram) agent.Service {
	return &metricsMiddleware{
		counter: counter,
		latency: latency,
		svc:     svc,
	}
}

func (ms *metricsMiddleware) Algo(ctx context.Context, algorithm agent.Algorithm) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "algo").Add(1)
		ms.latency.With("method", "algo").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Algo(ctx, algorithm)
}

func (ms *metricsMiddleware) Data(ctx context.Context, dataset agent.Dataset) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "data").Add(1)
		ms.latency.With("method", "data").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Data(ctx, dataset)
}

func (ms *metricsMiddleware) Result(ctx context.Context, consumer string) ([]byte, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "result").Add(1)
		ms.latency.With("method", "result").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Result(ctx, consumer)
}

func (ms *metricsMiddleware) Attestation(ctx context.Context, reportData [agent.ReportDataSize]byte) ([]byte, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "attestation").Add(1)
		ms.latency.With("method", "attestation").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Attestation(ctx, reportData)
}
