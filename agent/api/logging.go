// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

//go:build !test
// +build !test

package api

import (
	"fmt"
	"time"

	log "github.com/mainflux/mainflux/logger"
	"github.com/ultravioletrs/agent/agent"
)

var _ agent.Service = (*loggingMiddleware)(nil)

type loggingMiddleware struct {
	logger log.Logger
	svc    agent.Service
}

// LoggingMiddleware adds logging facilities to the core service.
func LoggingMiddleware(svc agent.Service, logger log.Logger) agent.Service {
	return &loggingMiddleware{logger, svc}
}

func (lm *loggingMiddleware) Ping(secret string) (response string, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method ping for secret %s took %s to complete", secret, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.Ping(secret)
}
