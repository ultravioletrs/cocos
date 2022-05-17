package computations

import (
	"context"
	"time"

	"github.com/mainflux/mainflux"
)

type Service interface {
	CreateComputation(ctx context.Context, token string, computation Computation) (string, error)
	ViewComputation(ctx context.Context, token, id string) (Computation, error)
	ListComputations(ctx context.Context, token string, meta PageMetadata) (Page, error)
	UpdateComputation(ctx context.Context, token string, computation Computation) error
	RemoveComputation(ctx context.Context, token, id string) error
}

type service struct {
	repo Repository
	idp  mainflux.IDProvider
}

func NewService(repo Repository, idp mainflux.IDProvider) Service {
	return service{
		repo: repo,
		idp:  idp,
	}
}

func (svc service) CreateComputation(ctx context.Context, token string, computation Computation) (string, error) {
	id, err := svc.idp.ID()
	if err != nil {
		return "", err
	}
	computation.ID = id
	computation.StartTime = time.Now()
	return svc.repo.Save(ctx, computation)
}

func (svc service) ViewComputation(ctx context.Context, token string, id string) (Computation, error) {
	return svc.repo.View(ctx, id)
}

func (svc service) ListComputations(ctx context.Context, token string, meta PageMetadata) (Page, error) {
	return svc.repo.RetrieveAll(ctx, token, meta)
}

func (svc service) UpdateComputation(ctx context.Context, token string, computation Computation) error {
	return svc.repo.Update(ctx, computation)
}

func (svc service) RemoveComputation(ctx context.Context, token string, id string) error {
	return svc.repo.Delete(ctx, id)
}
