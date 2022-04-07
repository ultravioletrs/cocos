package computations

import "context"

type Service interface {
	CreateComputation(ctx context.Context, token string, computation Computation) (string, error)
}

type service struct {
	repo Repository
}

func NewService(repo Repository) Service {
	return service{
		repo: repo,
	}
}

// CreateComputation implements Service
func (svc service) CreateComputation(ctx context.Context, token string, computation Computation) (string, error) {
	return svc.repo.Save(ctx, computation)
}
