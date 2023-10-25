// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build !test
// +build !test

package api

import (
	"context"
	"time"

	"github.com/go-kit/kit/metrics"
	"github.com/ultravioletrs/agent/agent"
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

func (ms *metricsMiddleware) Run(ctx context.Context, cmp agent.Computation) (string, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "run").Add(1)
		ms.latency.With("method", "run").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Run(ctx, cmp)
}

func (ms *metricsMiddleware) Algo(ctx context.Context, algorithm []byte) (string, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "algo").Add(1)
		ms.latency.With("method", "algo").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Algo(ctx, algorithm)
}

func (ms *metricsMiddleware) Data(ctx context.Context, dataset []byte) (string, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "data").Add(1)
		ms.latency.With("method", "data").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Data(ctx, dataset)
}

func (ms *metricsMiddleware) Result(ctx context.Context) ([]byte, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "result").Add(1)
		ms.latency.With("method", "result").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Result(ctx)
}

func (ms *metricsMiddleware) Attestation(ctx context.Context) ([]byte, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "attestation").Add(1)
		ms.latency.With("method", "attestation").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Attestation(ctx)
}
