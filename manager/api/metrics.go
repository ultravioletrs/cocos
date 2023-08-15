// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

//go:build !test
// +build !test

package api

import (
	"context"
	"os/exec"
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

func (ms *metricsMiddleware) CreateLibvirtDomain(ctx context.Context, pool, volume, domain string) (response string, err error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "CreateDomain").Add(1)
		ms.latency.With("method", "CreateDomain").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.CreateLibvirtDomain(ctx, pool, volume, domain)
}

func (ms *metricsMiddleware) CreateQemuVM(ctx context.Context, exe string, args []string) (*exec.Cmd, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "CreateQemuVM").Add(1)
		ms.latency.With("method", "CreateQemuVM").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.CreateQemuVM(ctx, exe, args)
}

func (ms *metricsMiddleware) Run(ctx context.Context, computation []byte) (string, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "Run").Add(1)
		ms.latency.With("method", "Run").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Run(ctx, computation)
}
