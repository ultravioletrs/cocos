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
	pkgmanager "github.com/ultravioletrs/cocos/pkg/manager"
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

func (ms *metricsMiddleware) Run(ctx context.Context, mc *pkgmanager.ComputationRunReq) (string, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "Run").Add(1)
		ms.latency.With("method", "Run").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Run(ctx, mc)
}

func (ms *metricsMiddleware) Stop(ctx context.Context, computationID string) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "Stop").Add(1)
		ms.latency.With("method", "Stop").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Stop(ctx, computationID)
}

func (ms *metricsMiddleware) RetrieveAgentEventsLogs() {
	ms.svc.RetrieveAgentEventsLogs()
}

func (ms *metricsMiddleware) FetchBackendInfo() ([]byte, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "FetchBackendInfo").Add(1)
		ms.latency.With("method", "FetchBackendInfo").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.FetchBackendInfo()
}
