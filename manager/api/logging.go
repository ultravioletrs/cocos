// Copyright (c) Mainflux
// SPDX-License-Identifier: Apache-2.0

//go:build !test
// +build !test

package api

import (
	"fmt"
	"time"

	log "github.com/mainflux/mainflux/logger"
	"github.com/ultravioletrs/manager/manager"
)

var _ manager.Service = (*loggingMiddleware)(nil)

type loggingMiddleware struct {
	logger log.Logger
	svc    manager.Service
}

// LoggingMiddleware adds logging facilities to the core service.
func LoggingMiddleware(svc manager.Service, logger log.Logger) manager.Service {
	return &loggingMiddleware{logger, svc}
}

func (lm *loggingMiddleware) CreateDomain(pool, volume, domain string) (response string, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method CreateDomain for pool %s, volume %s, and domain %s took %s to complete",
			pool, volume, domain, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())

	return lm.svc.CreateDomain(pool, volume, domain)
}

func (lm *loggingMiddleware) Run(computation []byte) (id string, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method Run for computation took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s with ID: %s", message, id))
	}(time.Now())

	return lm.svc.Run(computation)
}
