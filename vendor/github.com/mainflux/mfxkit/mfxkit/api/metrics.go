// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

// +build !test

package api

import (
	"time"

	"github.com/go-kit/kit/metrics"
	"github.com/mainflux/mfxkit/mfxkit"
)

var _ mfxkit.Service = (*metricsMiddleware)(nil)

type metricsMiddleware struct {
	counter metrics.Counter
	latency metrics.Histogram
	svc     mfxkit.Service
}

// MetricsMiddleware instruments core service by tracking request count and
// latency.
func MetricsMiddleware(svc mfxkit.Service, counter metrics.Counter, latency metrics.Histogram) mfxkit.Service {
	return &metricsMiddleware{
		counter: counter,
		latency: latency,
		svc:     svc,
	}
}

func (ms *metricsMiddleware) Ping(secret string) (response string, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "ping").Add(1)
		ms.latency.With("method", "ping").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Ping(secret)
}
