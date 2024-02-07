package logger

import (
	"context"
	"log/slog"
)

var _ slog.Handler = (*handler)(nil)

type handler struct {
	opts slog.HandlerOptions
}

// Enabled implements slog.Handler.
func (h *handler) Enabled(_ context.Context, l slog.Level) bool {
	minLevel := slog.LevelInfo
	if h.opts.Level != nil {
		minLevel = h.opts.Level.Level()
	}
	return l >= minLevel
}

// Handle implements slog.Handler.
func (*handler) Handle(context.Context, slog.Record) error {
	panic("unimplemented")
}

// WithAttrs implements slog.Handler.
func (*handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	panic("unimplemented")
}

// WithGroup implements slog.Handler.
func (*handler) WithGroup(name string) slog.Handler {
	panic("unimplemented")
}
