//go:build !test

package api

import (
	"context"
	"fmt"
	"time"

	log "github.com/mainflux/mainflux/logger"
	"github.com/ultravioletrs/cocos/computations"
)

var _ computations.Service = (*loggingMiddleware)(nil)

type loggingMiddleware struct {
	logger log.Logger
	svc    computations.Service
}

// LoggingMiddleware adds logging facilities to the core service.
func LoggingMiddleware(svc computations.Service, logger log.Logger) computations.Service {
	return &loggingMiddleware{logger, svc}
}

func (lm *loggingMiddleware) CreateComputation(ctx context.Context, token string, computation computations.Computation) (id string, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method create_computation for user %s took %s to complete", token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))

	}(time.Now())

	return lm.svc.CreateComputation(ctx, token, computation)
}
