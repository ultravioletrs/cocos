package tracing

import (
	"context"
	"os/exec"

	"github.com/ultravioletrs/manager/manager"
	"go.opentelemetry.io/otel/attribute"
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

func (tm *tracingMiddleware) CreateLibvirtDomain(ctx context.Context, pool, volume, domain string) (string, error) {
	ctx, span := tm.tracer.Start(ctx, "create", trace.WithAttributes(
		attribute.String("name", pool),
		attribute.String("volume", volume),
		attribute.String("domain", domain),
	))
	defer span.End()

	return tm.svc.CreateLibvirtDomain(ctx, pool, volume, domain)
}

func (tm *tracingMiddleware) CreateQemuVM(ctx context.Context, exe string, args []string) (*exec.Cmd, error) {
	ctx, span := tm.tracer.Start(ctx, "createQemuVM")
	defer span.End()

	return tm.svc.CreateQemuVM(ctx, exe, args)
}

func (tm *tracingMiddleware) Run(ctx context.Context, computation []byte) (string, error) {
	ctx, span := tm.tracer.Start(ctx, "run")
	defer span.End()

	return tm.svc.Run(ctx, computation)
}
