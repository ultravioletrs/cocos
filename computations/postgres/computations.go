package postgres

import (
	"context"

	"github.com/ultravioletrs/cocos/computations"
	psql "github.com/ultravioletrs/cocos/internal/postgres"
)

type computationRepo struct {
	db psql.Database
}

func NewRepository(db psql.Database) computations.Repository {
	return computationRepo{
		db: db,
	}
}

// Delete implements Repository
func (computationRepo) Delete(ctx context.Context, c computations.Computation) (string, error) {
	panic("unimplemented")
}

// Save implements Repository
func (computationRepo) Save(ctx context.Context, c computations.Computation) (string, error) {
	panic("unimplemented")
}

// Update implements Repository
func (computationRepo) Update(ctx context.Context, c computations.Computation) (string, error) {
	panic("unimplemented")
}

// View implements Repository
func (computationRepo) View(ctx context.Context, c computations.Computation) (string, error) {
	panic("unimplemented")
}
