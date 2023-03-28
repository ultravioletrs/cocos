// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

//go:build !test
// +build !test

package api

import (
	"time"

	"github.com/go-kit/kit/metrics"
	"github.com/ultravioletrs/manager/manager"
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

func (ms *metricsMiddleware) CreateDomain(pool, volume, domain string) (response string, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "CreateDomain").Add(1)
		ms.latency.With("method", "CreateDomain").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.CreateDomain(pool, volume, domain)
}
