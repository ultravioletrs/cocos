// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package tracing

import (
	"context"

	"github.com/ultravioletrs/cocos/manager"
	"go.opentelemetry.io/otel/trace"
)

var _ manager.Service = (*tracingMiddleware)(nil)

type tracingMiddleware struct {
	tracer trace.Tracer
	svc    manager.Service
}

// New returns a new auth service with tracing capabilities.
func New(svc manager.Service, tracer trace.Tracer) manager.Service {
	return &tracingMiddleware{tracer, svc}
}

func (tm *tracingMiddleware) CreateVM(ctx context.Context) (string, string, error) {
	ctx, span := tm.tracer.Start(ctx, "run")
	defer span.End()

	return tm.svc.CreateVM(ctx)
}

func (tm *tracingMiddleware) RemoveVM(ctx context.Context, id string) error {
	ctx, span := tm.tracer.Start(ctx, "stop")
	defer span.End()

	return tm.svc.RemoveVM(ctx, id)
}

func (tm *tracingMiddleware) FetchAttestationPolicy(ctx context.Context, computationId string) ([]byte, error) {
	_, span := tm.tracer.Start(ctx, "fetch_attestation_policy")
	defer span.End()

	return tm.svc.FetchAttestationPolicy(ctx, computationId)
}

func (tm *tracingMiddleware) ReturnSVMInfo(ctx context.Context) (string, int, string, string) {
	_, span := tm.tracer.Start(ctx, "return_svm_info")
	defer span.End()

	return tm.svc.ReturnSVMInfo(ctx)
}
