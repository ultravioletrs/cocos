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
	attestations "github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
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

// State implements agent.Service.
func (ms *metricsMiddleware) State() string {
	defer func(begin time.Time) {
		ms.counter.With("method", "state").Add(1)
		ms.latency.With("method", "state").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.State()
}

// InitComputation implements agent.Service.
func (ms *metricsMiddleware) InitComputation(ctx context.Context, cmp agent.Computation) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "init_computation").Add(1)
		ms.latency.With("method", "init_computation").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.InitComputation(ctx, cmp)
}

// StopComputation implements agent.Service.
func (ms *metricsMiddleware) StopComputation(ctx context.Context) error {
	defer func(begin time.Time) {
		ms.counter.With("method", "stop_computation").Add(1)
		ms.latency.With("method", "stop_computation").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.StopComputation(ctx)
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

func (ms *metricsMiddleware) Result(ctx context.Context) ([]byte, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "result").Add(1)
		ms.latency.With("method", "result").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Result(ctx)
}

func (ms *metricsMiddleware) Attestation(ctx context.Context, reportData [quoteprovider.Nonce]byte, nonce [vtpm.Nonce]byte, attType attestations.PlatformType) ([]byte, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "attestation").Add(1)
		ms.latency.With("method", "attestation").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.Attestation(ctx, reportData, nonce, attType)
}

func (ms *metricsMiddleware) IMAMeasurements(ctx context.Context) ([]byte, []byte, error) {
	defer func(begin time.Time) {
		ms.counter.With("method", "imameasurements").Add(1)
		ms.latency.With("method", "imameasurements").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return ms.svc.IMAMeasurements(ctx)
}
