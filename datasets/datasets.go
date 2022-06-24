package dataset

import (
	"context"
	"time"
)

type Dataset struct {
	ID          string    `json:"id,omitempty" db:"id"`
	Name        string    `json:"name,omitempty" db:"name"`
	Description string    `json:"description,omitempty" db:"description"`
	Owner       string    `json:"owner,omitempty" db:"owner"`
	Size        uint64    `json:"size,omitempty" db:"size"`
	Type        string    `json:"type,omitempty" db:"type"`
	CreatedAt   time.Time `json:"createdat,omitempty" db:"createdat"`
	UpdatedAt   time.Time `json:"updatedat,omitempty" db:"updatedat"`
	Location    string    `json:"location,omitempty" db:"location"`
	Format      string    `json:"format,omitempty" db:"format"`
	Metadata    Metadata  `json:"metadata,omitempty" db:"metadata"`
}

type Metadata map[string]interface{}

type PageMetadata struct {
	Total    uint64   `json:"total,omitempty"`
	Offset   uint64   `json:"offset,omitempty"`
	Limit    uint64   `json:"limit,omitempty"`
	Name     string   `json:"name,omitempty"`
	Order    string   `json:"order,omitempty"`
	Dir      string   `json:"dir,omitempty"`
	Metadata Metadata `json:"metadata,omitempty"`
}

type Page struct {
	PageMetadata
	Datasets []Dataset `json:"datasets,omitempty"`
}

func (d Dataset) Validate() error {
	return nil
}

// DatasetRepository specifies a dataset persistence API.
type DatasetRepository interface {
	// Save persists multiple datasets. Datasets are saved using a transaction. If one dataset
	// fails then none will be saved. Successful operation is indicated by non-nil
	// error response.
	Save(ctx context.Context, d Dataset) (string, error)

	// View returns Dataset with given ID belonging to the user identified by the given token.
	View(ctx context.Context, id string) (Dataset, error)

	// RetrieveAll retrieves the subset of datasets owned by the specified user
	RetrieveAll(ctx context.Context, owner string, pm PageMetadata) (Page, error)

	// Update performs an update to the existing dataset. A non-nil error is
	// returned to indicate operation failure.
	Update(ctx context.Context, d Dataset) error

	// Remove removes the dataset having the provided identifier, that is owned
	// by the specified user.
	Delete(ctx context.Context, id string) error
}
