package computations

import "context"

type Service interface {
	CreateComputation(ctx context.Context, token string, computation Computation) (string, error)
}

type service struct {
}

func New() Service {
	return service{}
}

// CreateComputation implements Service
func (service) CreateComputation(ctx context.Context, token string, computation Computation) (string, error) {
	panic("unimplemented")
}
