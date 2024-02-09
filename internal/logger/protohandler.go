package logger

import (
	"context"
	"io"
	"log/slog"

	"github.com/ultravioletrs/cocos/pkg/manager"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var _ slog.Handler = (*handler)(nil)

type handler struct {
	opts slog.HandlerOptions
	w    io.Writer
}

func NewProtoHandler(w io.Writer, opts *slog.HandlerOptions) slog.Handler {
	if opts == nil {
		opts = &slog.HandlerOptions{}
	}
	return &handler{
		opts: *opts,
		w:    w,
	}
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
func (h *handler) Handle(_ context.Context, r slog.Record) error {
	agentLog := manager.ClientStreamMessage{Message: &manager.ClientStreamMessage_AgentLog{AgentLog: &manager.AgentLog{
		Timestamp: timestamppb.New(r.Time),
		Message:   r.Message,
		Level:     r.Level.String(),
	}}}

	b, err := proto.Marshal(&agentLog)
	if err != nil {
		return err
	}
	if _, err := h.w.Write(b); err != nil {
		return err
	}
	return nil
}

// WithAttrs implements slog.Handler.
func (*handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	panic("unimplemented")
}

// WithGroup implements slog.Handler.
func (*handler) WithGroup(name string) slog.Handler {
	panic("unimplemented")
}
