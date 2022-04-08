package computations

import "context"

type Computation struct {
	ID                 string      `json:"id,omitempty"`
	Name               string      `json:"name,omitempty"`
	Description        string      `json:"description,omitempty"`
	Status             string      `json:"status,omitempty"`
	Owner              string      `json:"owner,omitempty"`
	StartTime          float64     `json:"startTime,omitempty"`
	EndTime            float64     `json:"endTime,omitempty"`
	Datasets           []string    `json:"datasets,omitempty"`
	Algorithms         []string    `json:"algorithms,omitempty"`
	DatasetProviders   []string    `json:"datasetProviders,omitempty"`
	AlgorithmProviders []string    `json:"algorithmProviders,omitempty"`
	Ttl                int         `json:"ttl,omitempty"`
	Metadata           interface{} `json:"metadata,omitempty"`
}

func (c Computation) Validate() error {
	return nil
}

type Repository interface {
	Save(context.Context, Computation) (string, error)
	View(context.Context, Computation) (string, error)
	Update(context.Context, Computation) (string, error)
	Delete(context.Context, Computation) (string, error)
}

type computationRepo struct {
}

func NewRepository() Repository {
	return computationRepo{}
}

// Delete implements Repository
func (computationRepo) Delete(context.Context, Computation) (string, error) {
	panic("unimplemented")
}

// Save implements Repository
func (computationRepo) Save(context.Context, Computation) (string, error) {
	panic("unimplemented")
}

// Update implements Repository
func (computationRepo) Update(context.Context, Computation) (string, error) {
	panic("unimplemented")
}

// View implements Repository
func (computationRepo) View(context.Context, Computation) (string, error) {
	panic("unimplemented")
}
