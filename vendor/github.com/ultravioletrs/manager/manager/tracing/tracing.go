package tracing

import (
	"context"

	"github.com/ultravioletrs/manager/manager"
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

func (tm *tracingMiddleware) Run(ctx context.Context, computation []byte) (string, error) {
	ctx, span := tm.tracer.Start(ctx, "run")
	defer span.End()

	return tm.svc.Run(ctx, computation)
}
