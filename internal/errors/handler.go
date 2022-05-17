package errors

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	log "github.com/mainflux/mainflux/logger"
)

func Handle(svcName string, l log.Logger, ctx context.Context, cancel context.CancelFunc) func() error {
	return func() error {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT, syscall.SIGABRT)
		select {
		case sig := <-c:
			cancel()
			l.Info(fmt.Sprintf("%s service canceled by signal: %s", svcName, sig))
		case <-ctx.Done():
			return nil
		}
		return nil
	}
}
