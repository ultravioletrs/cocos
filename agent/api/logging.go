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

	"github.com/ultravioletrs/cocos/agent"
	config "github.com/ultravioletrs/cocos/pkg/attestation"
	"github.com/ultravioletrs/cocos/pkg/attestation/quoteprovider"
	"github.com/ultravioletrs/cocos/pkg/attestation/vtpm"
)

var _ agent.Service = (*loggingMiddleware)(nil)

type loggingMiddleware struct {
	logger *slog.Logger
	svc    agent.Service
}

// LoggingMiddleware adds logging facilities to the core service.
func LoggingMiddleware(svc agent.Service, logger *slog.Logger) agent.Service {
	return &loggingMiddleware{logger, svc}
}

// State implements agent.Service.
func (lm *loggingMiddleware) State() (state string) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method State took %s to complete with state %s", time.Since(begin), state)
		lm.logger.Info(message)
	}(time.Now())
	return lm.svc.State()
}

// InitComputation implements agent.Service.
func (lm *loggingMiddleware) InitComputation(ctx context.Context, cmp agent.Computation) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method InitComputation for computation id %s took %s to complete", cmp.ID, time.Since(begin))
		if err != nil {
			lm.logger.WithGroup(cmp.ID).Warn(fmt.Sprintf("%s with error: %s", message, err))
			return
		}
		lm.logger.WithGroup(cmp.ID).Info(fmt.Sprintf("%s without errors", message))
	}(time.Now())

	return lm.svc.InitComputation(ctx, cmp)
}

// StopComputation implements agent.Service.
func (lm *loggingMiddleware) StopComputation(ctx context.Context) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method StopComputation took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors", message))
	}(time.Now())

	return lm.svc.StopComputation(ctx)
}

func (lm *loggingMiddleware) Algo(ctx context.Context, algorithm agent.Algorithm) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method Algo took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors", message))
	}(time.Now())

	return lm.svc.Algo(ctx, algorithm)
}

func (lm *loggingMiddleware) Data(ctx context.Context, dataset agent.Dataset) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method Data took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors", message))
	}(time.Now())

	return lm.svc.Data(ctx, dataset)
}

func (lm *loggingMiddleware) Result(ctx context.Context) (response []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method Result took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors", message))
	}(time.Now())

	return lm.svc.Result(ctx)
}

func (lm *loggingMiddleware) Attestation(ctx context.Context, reportData [quoteprovider.Nonce]byte, nonce [vtpm.Nonce]byte, attType config.AttestationType) (response []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method Attestation took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors", message))
	}(time.Now())

	return lm.svc.Attestation(ctx, reportData, nonce, attType)
}

func (lm *loggingMiddleware) IMAMeasurements(ctx context.Context) (file []byte, pcr10 []byte, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method IMAMeasurements took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors", message))
	}(time.Now())

	return lm.svc.IMAMeasurements(ctx)
}
