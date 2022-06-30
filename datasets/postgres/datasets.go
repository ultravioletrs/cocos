package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/mainflux/mainflux/pkg/errors"
	"github.com/ultravioletrs/cocos/datasets"
	"github.com/ultravioletrs/cocos/internal/db"
)

var _ datasets.DatasetRepository = (*datasetRepo)(nil)

type datasetRepo struct {
	db db.Database
}

func NewRepository(db db.Database) datasets.DatasetRepository {
	return datasetRepo{
		db: db,
	}
}

func (repo datasetRepo) Save(ctx context.Context, d datasets.Dataset) (string, error) {
	return "", nil
}

func (repo datasetRepo) View(ctx context.Context, id string) (datasets.Dataset, error) {
	dbds := dbDataset{ID: id}
	return toDataset(dbds)
}

func (repo datasetRepo) RetrieveAll(ctx context.Context, owner string, pm datasets.PageMetadata) (datasets.Page, error) {
	page := datasets.Page{
		PageMetadata: datasets.PageMetadata{
			Offset: pm.Offset,
			Limit:  pm.Limit,
			Order:  pm.Order,
			Dir:    pm.Dir,
		},
	}
	return page, nil
}

func (repo datasetRepo) Update(ctx context.Context, d datasets.Dataset) error {
	return nil
}

func (repo datasetRepo) Delete(ctx context.Context, id string) error {
	return nil
}

type dbDataset struct {
	ID          string    `db:"id"`
	Owner       string    `db:"owner"`
	Name        string    `db:"name"`
	Metadata    []byte    `db:"metadata"`
	Description string    `db:"description"`
	Size        uint64    `db:"size"`
	Type        string    `db:"type"`
	CreatedAt   time.Time `db:"createdat"`
	UpdatedAt   time.Time `db:"updatedat"`
	Location    string    `db:"location"`
	Format      string    `db:"format"`
}

func todbDataset(ds datasets.Dataset) (dbDataset, error) {
	data := []byte("{}")
	if len(ds.Metadata) > 0 {
		b, err := json.Marshal(ds.Metadata)
		if err != nil {
			return dbDataset{}, errors.Wrap(errors.ErrMalformedEntity, err)
		}
		data = b
	}

	return dbDataset{
		ID:          ds.ID,
		Owner:       ds.Owner,
		Name:        ds.Name,
		Description: ds.Description,
		Metadata:    data,
	}, nil
}

func toDataset(dbds dbDataset) (datasets.Dataset, error) {
	var metadata map[string]interface{}
	if err := json.Unmarshal([]byte(dbds.Metadata), &metadata); err != nil {
		return datasets.Dataset{}, errors.Wrap(errors.ErrMalformedEntity, err)
	}

	return datasets.Dataset{
		ID:          dbds.ID,
		Owner:       dbds.Owner,
		Name:        dbds.Name,
		Description: dbds.Description,
		Metadata:    metadata,
	}, nil
}
