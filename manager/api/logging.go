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

func (lm *loggingMiddleware) Run(ctx context.Context, mc *manager.ComputationRunReq) (agentAddr string, err error) {
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

func (lm *loggingMiddleware) Stop(ctx context.Context, computationID string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method Stop for computation took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())

	return lm.svc.Stop(ctx, computationID)
}

func (lm *loggingMiddleware) FetchBackendInfo(ctx context.Context, cmpId string) (body []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method FetchBackendInfo  for computation %s took %s to complete", cmpId, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}

		lm.logger.Info(message)
	}(time.Now())

	return lm.svc.FetchBackendInfo(ctx, cmpId)
}

func (lm *loggingMiddleware) ReportBrokenConnection(addr string) {
	lm.svc.ReportBrokenConnection(addr)
}

func (lm *loggingMiddleware) ReturnSVMInfo(ctx context.Context) (string, int, string, string) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method ReturnSVMInfo for computation took %s to complete", time.Since(begin))
		lm.logger.Info(message)
	}(time.Now())

	return lm.svc.ReturnSVMInfo(ctx)
}
