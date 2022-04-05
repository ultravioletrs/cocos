package computations

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
