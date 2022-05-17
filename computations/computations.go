package computations

import (
	"context"
	"time"
)

type Computation struct {
	ID                 string    `json:"id,omitempty" db:"id"`
	Name               string    `json:"name,omitempty" db:"name"`
	Description        string    `json:"description,omitempty" db:"description"`
	Status             string    `json:"status,omitempty" db:"status"`
	Owner              string    `json:"owner,omitempty" db:"owner"`
	StartTime          time.Time `json:"start_time,omitempty" db:"start_time"`
	EndTime            time.Time `json:"end_time,omitempty" db:"end_time"`
	Datasets           []string  `json:"datasets,omitempty" db:"datasets"`
	Algorithms         []string  `json:"algorithms,omitempty" db:"algorithms"`
	DatasetProviders   []string  `json:"dataset_providers,omitempty" db:"dataset_providers"`
	AlgorithmProviders []string  `json:"algorithm_providers,omitempty" db:"algorithm_providers"`
	Ttl                int       `json:"ttl,omitempty" db:"ttl"`
	Metadata           Metadata  `json:"metadata,omitempty" db:"metadata"`
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
	Computations []Computation `json:"computations,omitempty"`
}

func (c Computation) Validate() error {
	return nil
}

type Repository interface {
	Save(ctx context.Context, c Computation) (string, error)
	View(ctx context.Context, id string) (Computation, error)
	RetrieveAll(ctx context.Context, owner string, pm PageMetadata) (Page, error)
	Update(ctx context.Context, c Computation) error
	Delete(ctx context.Context, id string) error
}
