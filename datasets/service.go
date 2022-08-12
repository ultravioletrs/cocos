package datasets

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/mainflux/mainflux"
)

type datasetsService struct {
	repo DatasetRepository
	idp  mainflux.IDProvider
}

func NewService(repo DatasetRepository, idp mainflux.IDProvider) Service {
	return &datasetsService{
		repo: repo,
		idp:  idp,
	}
}

// Service specifies an API that must be fulfiled by the domain service
// implementation, and all of its decorators (e.g. logging & metrics).
type Service interface {
	// CreateDatasets adds datasets to the user.
	CreateDataset(ctx context.Context, dataset Dataset) (string, error)

	// ViewDataset retrieves data about the dataset identified with the provided
	// ID, that belongs to the user identified by the provided token.
	ViewDataset(ctx context.Context, owner, id string) (Dataset, error)

	// ListDatasets retrieves data about subset of datasets that belongs to the
	// user identified by the provided token.
	ListDatasets(ctx context.Context, owner string, meta PageMetadata) (Page, error)

	// UpdateDataset updates the dataset identified by the provided ID, that
	// belongs to the user identified by the provided token.
	UpdateDataset(ctx context.Context, dataset Dataset) error

	// UploadDataset uploads the actual dataset content to the dataset path.
	UploadDataset(ctx context.Context, id, owner string, payload []byte) error

	// RemoveDataset removes the dataset identified with the provided ID, that
	// belongs to the user identified by the provided token.
	RemoveDataset(ctx context.Context, id string) error
}

func (ds *datasetsService) CreateDataset(ctx context.Context, dataset Dataset) (string, error) {
	id, err := ds.idp.ID()
	if err != nil {
		return "", err
	}
	dataset.ID = id
	dataset.CreatedAt = time.Now()
	return ds.repo.Save(ctx, dataset)
}

func (ds *datasetsService) ViewDataset(ctx context.Context, owner, id string) (Dataset, error) {
	return ds.repo.RetrieveByID(ctx, owner, id)
}

func (ds *datasetsService) ListDatasets(ctx context.Context, owner string, pm PageMetadata) (Page, error) {
	page, err := ds.repo.RetrieveAll(ctx, owner, pm)
	if err != nil {
		return Page{}, err
	}
	return page, nil
}

func (ds *datasetsService) UpdateDataset(ctx context.Context, dataset Dataset) error {
	return ds.repo.Update(ctx, dataset)
}

func (ds *datasetsService) UploadDataset(ctx context.Context, id, owner string, payload []byte) error {
	dataset, err := ds.repo.RetrieveByID(ctx, owner, id)
	if err != nil {
		return err
	}
	path := filepath.Join(dataset.Path, dataset.ID)
	file, err := os.Create(id)
	if err != nil {
		return err
	}
	defer file.Close()
	filename := path
	err = os.WriteFile(filename, payload, fs.ModePerm)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, payload, fs.ModePerm)
}

func (ds *datasetsService) RemoveDataset(ctx context.Context, id string) error {
	if err := ds.repo.Delete(ctx, id); err != nil {
		return err
	}
	return ds.repo.Delete(ctx, id)
}
