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

func (lm *loggingMiddleware) CreateDataset(ctx context.Context, dts datasets.Dataset) (id string, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method create_dataset took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())
	return lm.svc.CreateDataset(ctx, dts)
}

func (lm *loggingMiddleware) ViewDataset(ctx context.Context, owner, id string) (d datasets.Dataset, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method view_dataset took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())
	return lm.svc.ViewDataset(ctx, owner, id)
}

func (lm *loggingMiddleware) ListDatasets(ctx context.Context, owner string, meta datasets.PageMetadata) (page datasets.Page, err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method list_datasets took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())
	return lm.svc.ListDatasets(ctx, owner, meta)
}

func (lm *loggingMiddleware) UpdateDataset(ctx context.Context, dataset datasets.Dataset) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method update_dataset took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())
	return lm.svc.UpdateDataset(ctx, dataset)
}

func (lm *loggingMiddleware) UploadDataset(ctx context.Context, id, owner string, payload []byte) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method upload_dataset took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())
	return lm.svc.UploadDataset(ctx, id, owner, payload)
}

func (lm *loggingMiddleware) RemoveDataset(ctx context.Context, id string) (err error) {
	defer func(begin time.Time) {
		message := fmt.Sprintf("Method remove_dataset took %s to complete", time.Since(begin))
		if err != nil {
			lm.logger.Warn(fmt.Sprintf("%s with error: %s.", message, err))
			return
		}
		lm.logger.Info(fmt.Sprintf("%s without errors.", message))
	}(time.Now())
	return lm.svc.RemoveDataset(ctx, id)
}
