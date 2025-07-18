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

func (lm *loggingMiddleware) CreateVM(ctx context.Context, req *manager.CreateReq) (agentAddr string, id string, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method CreateVM for id %s on port %s took %s to complete", id, agentAddr, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())

	return lm.svc.CreateVM(ctx, req)
}

func (lm *loggingMiddleware) RemoveVM(ctx context.Context, id string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method RemoveVM for vm %s took %s to complete", id, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(message)
	}(time.Now())

	return lm.svc.RemoveVM(ctx, id)
}

func (lm *loggingMiddleware) FetchAttestationPolicy(ctx context.Context, cmpId string) (body []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method FetchAttestation  for computation %s took %s to complete", cmpId, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}

		lm.logger.Info(message)
	}(time.Now())

	return lm.svc.FetchAttestationPolicy(ctx, cmpId)
}

func (lm *loggingMiddleware) ReturnCVMInfo(ctx context.Context) (string, int, string, string) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method ReturnCVMInfo for computation took %s to complete", time.Since(begin))
		lm.logger.Info(message)
	}(time.Now())

	return lm.svc.ReturnCVMInfo(ctx)
}

func (lm *loggingMiddleware) Shutdown() (err error) {
	defer func(begin time.Time) {
		if err != nil {
			lm.logger.Warn("Method Shutdown completed with error",
				"time_taken", time.Since(begin),
				"error", err,
			)
			return
		}
		lm.logger.Info("Method Shutdown completed successfully",
			"time_taken", time.Since(begin),
		)
	}(time.Now())

	return lm.svc.Shutdown()
}
