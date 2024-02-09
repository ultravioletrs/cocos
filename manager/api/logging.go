// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0

//go:build !test
// +build !test

package api

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ultravioletrs/cocos/manager"
	pkgmanager "github.com/ultravioletrs/cocos/pkg/manager"
)

var _ manager.Service = (*loggingMiddleware)(nil)

type loggingMiddleware struct {
	logger *slog.Logger
	svc    manager.Service
}

// LoggingMiddleware adds logging facilities to the core service.
func LoggingMiddleware(svc manager.Service, logger *slog.Logger) manager.Service {
	return &loggingMiddleware{logger, svc}
}

func (lm *loggingMiddleware) Run(ctx context.Context, mc *pkgmanager.ComputationRunReq) (agentAddr string, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method Run for computation took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())

	return lm.svc.Run(ctx, mc)
}

func (tm *loggingMiddleware) RetrieveAgentEventsLogs() {
	// no logging required.
}
