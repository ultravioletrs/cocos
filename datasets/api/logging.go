package api

import (
	"context"
	"fmt"
	"time"

	log "github.com/mainflux/mainflux/logger"

	"github.com/ultravioletrs/cocos/datasets"
)

var _ datasets.Service = (*loggingMiddleware)(nil)

type loggingMiddleware struct {
	logger log.Logger
	svc    datasets.Service
}

// LoggingMiddleware adds logging facilities to the core service.
func LoggingMiddleware(svc datasets.Service, logger log.Logger) datasets.Service {
	return &loggingMiddleware{logger, svc}
}

func (lm *loggingMiddleware) CreateDataset(ctx context.Context, token string, dataset datasets.Dataset) (id string, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method create_dataset for user %s took %s to complete", token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())
	return lm.svc.CreateDataset(ctx, token, dataset)
}

func (lm *loggingMiddleware) ViewDataset(ctx context.Context, token, id string) (c datasets.Dataset, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method view_dataset for user %s took %s to complete", token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())
	return lm.svc.ViewDataset(ctx, token, id)
}

func (lm *loggingMiddleware) ListDatasets(ctx context.Context, token string, meta datasets.PageMetadata) (page datasets.Page, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_datasets for user %s took %s to complete", token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())
	return lm.svc.ListDatasets(ctx, token, meta)
}

func (lm *loggingMiddleware) UpdateDataset(ctx context.Context, token string, dataset datasets.Dataset) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_dataset for user %s took %s to complete", token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())
	return lm.svc.UpdateDataset(ctx, token, dataset)
}

func (lm *loggingMiddleware) RemoveDataset(ctx context.Context, token, id string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method remove_dataset for user %s took %s to complete", token, time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())
	return lm.svc.RemoveDataset(ctx, token, id)
}
