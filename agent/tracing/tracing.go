// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package tracing

import (
	"context"

	"github.com/ultravioletrs/cocos/agent"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

var _ agent.Service = (*tracingMiddleware)(nil)

type tracingMiddleware struct {
	tracer trace.Tracer
	svc    agent.Service
}

// New returns a new auth service with tracing capabilities.
func New(svc agent.Service, tracer trace.Tracer) agent.Service {
	return &tracingMiddleware{tracer, svc}
}

func (tm *tracingMiddleware) Run(ctx context.Context, cmp agent.Computation) (string, error) {
	ctx, span := tm.tracer.Start(ctx, "run", trace.WithAttributes(
		attribute.String("id", cmp.ID),
		attribute.String("name", cmp.Name),
		attribute.String("description", cmp.Description),
		attribute.String("status", cmp.Status),
		attribute.String("start_time", cmp.StartTime.String()),
		attribute.String("end_time", cmp.EndTime.String()),
		attribute.StringSlice("result_consumers", cmp.ResultConsumers),
		attribute.Stringer("datasets", &cmp.Datasets),
		attribute.Stringer("algorithms", &cmp.Algorithms),
	))
	defer span.End()

	return tm.svc.Run(ctx, cmp)
}

func (tm *tracingMiddleware) Algo(ctx context.Context, algorithm agent.Algorithm) (string, error) {
	ctx, span := tm.tracer.Start(ctx, "algo")
	defer span.End()

	return tm.svc.Algo(ctx, algorithm)
}

func (tm *tracingMiddleware) Data(ctx context.Context, dataset agent.Dataset) (string, error) {
	ctx, span := tm.tracer.Start(ctx, "data")
	defer span.End()

	return tm.svc.Data(ctx, dataset)
}

func (tm *tracingMiddleware) Result(ctx context.Context, consumer string) ([]byte, error) {
	ctx, span := tm.tracer.Start(ctx, "result")
	defer span.End()

	return tm.svc.Result(ctx, consumer)
}

func (tm *tracingMiddleware) Attestation(ctx context.Context) ([]byte, error) {
	ctx, span := tm.tracer.Start(ctx, "attestation")
	defer span.End()

	return tm.svc.Attestation(ctx)
}
