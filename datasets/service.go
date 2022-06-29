package datasets

import (
	"context"
)

// Service specifies an API that must be fulfiled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type Service interface {
	// CreateDatasets adds datasets to the user.
	CreateDataset(ctx context.Context, token string, dataset Dataset) (string, error)

	// ViewDataset retrieves data about the dataset identified with the provided
	// ID, that belongs to the user identified by the provided token.
	ViewDataset(ctx context.Context, token, id string) (Dataset, error)

	// ListDatasets retrieves data about subset of datasets that belongs to the
	// user identified by the provided token.
	ListDatasets(ctx context.Context, token string, meta PageMetadata) (Page, error)

	// UpdateDataset updates the dataset identified by the provided ID, that
	// belongs to the user identified by the provided token.
	UpdateDataset(ctx context.Context, token string, dataset Dataset) error

	// RemoveDataset removes the dataset identified with the provided ID, that
	// belongs to the user identified by the provided token.
	RemoveDataset(ctx context.Context, token, id string) error
}
