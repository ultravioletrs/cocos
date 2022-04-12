package http

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/mainflux/mainflux/logger"
)

const stopWaitTime = 5 * time.Second

func StartHTTPServer(ctx context.Context, name, port, cert, key string, handler http.Handler, logger logger.Logger) error {
	p := fmt.Sprintf(":%s", port)
	errCh := make(chan error)
	server := &http.Server{Addr: p, Handler: handler}

	switch {
	case cert != "" || key != "":
		logger.Info(fmt.Sprintf("%s service started using https on port %s with cert %s key %s",
			name, port, cert, key))
		go func() {
			errCh <- server.ListenAndServeTLS(cert, key)
		}()
	default:
		logger.Info(fmt.Sprintf("%s service started using http on port %s", name, port))
		go func() {
			errCh <- server.ListenAndServe()
		}()
	}

	select {
	case <-ctx.Done():
		ctxShutdown, cancelShutdown := context.WithTimeout(context.Background(), stopWaitTime)
		defer cancelShutdown()
		if err := server.Shutdown(ctxShutdown); err != nil {
			logger.Error(fmt.Sprintf("%s service error occurred during shutdown at %s: %s", name, p, err))
			return fmt.Errorf("%s service occurred during shutdown at %s: %w", name, p, err)
		}
		logger.Info(fmt.Sprintf("%s service shutdown of http at %s", name, p))
		return nil
	case err := <-errCh:
		return err
	}

}
